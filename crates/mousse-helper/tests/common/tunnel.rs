//! A TLS-terminating stand-in for a tunnel, for helpers started by a test:
//! TLS on a loopback port with a certificate for `localhost` signed by a
//! test root, plain bytes on to a target port. A helper trusts the root
//! through `MOUSSE_NET_TEST_EXTRA_ROOT` (debug builds only). Test files
//! include it with `#[path]`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A test root and a certificate for `localhost` it signs.
pub struct Pki {
    root: CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Pki {
    pub fn new(label: &str) -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, format!("mousse-net test root {label}"));
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        leaf.distinguished_name
            .push(DnType::CommonName, "localhost");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
        Pki {
            root: ca_cert.der().clone(),
            chain: vec![leaf_cert.der().clone(), ca_cert.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        }
    }

    /// Write the root to `dir`: the file to name in
    /// `MOUSSE_NET_TEST_EXTRA_ROOT`.
    pub fn root_file(&self, dir: &Path) -> PathBuf {
        let file = dir.join("tunnel-root.der");
        std::fs::write(&file, self.root.as_ref()).unwrap();
        file
    }
}

/// Stand-ins running on their own runtime, as long as this lives.
pub struct Tunnels {
    rt: tokio::runtime::Runtime,
}

impl Default for Tunnels {
    fn default() -> Self {
        Self::new()
    }
}

impl Tunnels {
    pub fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        Tunnels { rt }
    }

    /// A stand-in with `pki`'s certificate that carries each connection on
    /// to loopback port `target`. Its port.
    pub fn stand_in(&self, pki: &Pki, target: u16) -> u16 {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(pki.chain.clone(), pki.key.clone_key())
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = self
            .rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        self.rt.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut plain) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
                });
            }
        });
        port
    }
}

/// The `wss` route of a stand-in on `port`, canonical.
pub fn route(port: u16) -> String {
    format!("wss://localhost:{port}/t/mousse-net/1")
}
