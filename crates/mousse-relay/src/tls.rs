//! TLS for the outer connection (spec `relay.md` 2): TLS 1.3 only, ALPN
//! `http/1.1`, no resumption or early data, the relay certificate of 2.1,
//! and the native client's pin on the relay id.

use std::fmt;
use std::sync::Arc;

use mousse_net_core::identity::{RawSignature, SoftwareKey};
use mousse_net_core::relay::cert::{certificate_key, check_pin};
use mousse_net_core::relay::proof::OUTER_EXPORTER_LABEL;
use mousse_net_core::relay::{relay_certificate, RelayId};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime as PkiTime};
use rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    CertificateError, ClientConfig, CommonState, DigitallySignedStruct, Error, NamedGroup,
    ServerConfig, SignatureAlgorithm, SignatureScheme,
};

/// ALPN of the outer connection.
pub const ALPN: &[u8] = b"http/1.1";

/// The only `CertificateVerify` scheme.
pub const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

/// The group native clients require.
pub const NATIVE_GROUP: NamedGroup = NamedGroup::X25519MLKEM768;

/// The groups the relay offers, the hybrid group first.
pub const RELAY_GROUPS: [NamedGroup; 2] = [NamedGroup::X25519MLKEM768, NamedGroup::X25519];

fn provider_with(groups: &[NamedGroup]) -> Arc<CryptoProvider> {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    let all = std::mem::take(&mut p.kx_groups);
    p.kx_groups = groups
        .iter()
        .filter_map(|name| all.iter().find(|g| g.name() == *name).copied())
        .collect();
    Arc::new(p)
}

struct RelaySigningKey(Arc<SoftwareKey>);

impl fmt::Debug for RelaySigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelaySigningKey(..)")
    }
}

impl SigningKey for RelaySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SCHEME)
            .then(|| Box::new(RelaySigner(self.0.clone())) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

struct RelaySigner(Arc<SoftwareKey>);

impl fmt::Debug for RelaySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelaySigner(..)")
    }
}

impl Signer for RelaySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.sign_raw(message).to_der())
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

#[derive(Debug)]
struct RelayCert(Arc<CertifiedKey>);

impl ResolvesServerCert for RelayCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The relay's TLS server configuration for its identity key.
pub fn server_config(identity: SoftwareKey) -> Arc<ServerConfig> {
    let cert = CertificateDer::from(relay_certificate(&identity));
    let key = Arc::new(CertifiedKey::new(
        vec![cert],
        Arc::new(RelaySigningKey(Arc::new(identity))),
    ));
    let mut config = ServerConfig::builder_with_provider(provider_with(&RELAY_GROUPS))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(RelayCert(key)));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Arc::new(config)
}

/// The native client's check of the relay: the pin, then
/// `CertificateVerify` with the pinned key.
#[derive(Debug)]
struct PinnedRelay(RelayId);

impl ServerCertVerifier for PinnedRelay {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: PkiTime,
    ) -> Result<ServerCertVerified, Error> {
        check_pin(end_entity.as_ref(), &self.0).map_err(|_| {
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        })?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != SCHEME {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        let key = certificate_key(cert.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let sig = RawSignature::from_der(dss.signature())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadSignature))?;
        key.verify(message, &sig)
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadSignature))?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}

/// A native client's configuration for a relay with id `pin`: TLS 1.3,
/// only the hybrid group, no resumption.
pub fn client_config(pin: RelayId) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(provider_with(&[NATIVE_GROUP]))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedRelay(pin)))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

/// The checks after a handshake: ALPN and, for a native client, the hybrid
/// group.
pub fn check(conn: &CommonState, native: bool) -> Result<(), String> {
    if conn.alpn_protocol() != Some(ALPN) {
        return Err("the relay connection did not negotiate http/1.1".into());
    }
    if native && conn.negotiated_key_exchange_group().map(|g| g.name()) != Some(NATIVE_GROUP) {
        return Err("the relay connection did not use X25519MLKEM768".into());
    }
    Ok(())
}

/// The outer exporter of a finished connection.
pub fn exporter<D>(conn: &rustls::ConnectionCommon<D>) -> Result<[u8; 32], Error> {
    conn.export_keying_material([0u8; 32], OUTER_EXPORTER_LABEL, None)
}
