//! Mutual TLS 1.3 between two devices on session certificates (step 1).
//!
//! - TLS 1.3 only, mandatory client certificates, ALPN `mousse/1`.
//! - The only signature scheme is `ecdsa_secp256r1_sha256`.
//! - Both verifiers call [`session_cert::verify`]. The caller passes the
//!   stored pin (or, on first contact, the ticket's host identity) on every
//!   connection. The host passes no pin; step 2 decides what the peer may do.
//! - No session resumption and no tickets, so every connection runs the
//!   verifier again.
//! - Key exchange is X25519MLKEM768 or X25519 (aws-lc-rs). With
//!   [`TlsPolicy::require_hybrid`] a connection that did not negotiate the
//!   hybrid group is closed after the handshake.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::pairing::{SessionExporters, JOIN_EXPORTER_LABEL, PAIR_EXPORTER_LABEL};
use mousse_net_core::session_cert::{
    self, CertError, SessionCertificate, SessionKey, ValidityWindow, VerifiedSessionCert,
};
use mousse_net_core::ALPN;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, Resumption};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime as PkiTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::time_provider::TimeProvider;
use rustls::{
    CertificateError, ClientConfig, CommonState, DigitallySignedStruct, DistinguishedName, Error,
    NamedGroup, OtherError, ServerConfig, SignatureAlgorithm, SignatureScheme,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::clock::Clock;
use crate::error::NetError;
use crate::pipe::Pipe;

/// The only `CertificateVerify` scheme peers use.
pub const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

/// How long a TLS handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Session policy knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsPolicy {
    /// Close a connection that did not negotiate X25519MLKEM768. Native
    /// peers always offer it, so this catches a build that lost it.
    pub require_hybrid: bool,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            require_hybrid: true,
        }
    }
}

/// The aws-lc-rs provider with the hybrid group preferred, trimmed to
/// X25519MLKEM768 and X25519.
pub fn provider() -> Arc<CryptoProvider> {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    p.kx_groups
        .retain(|g| matches!(g.name(), NamedGroup::X25519MLKEM768 | NamedGroup::X25519));
    Arc::new(p)
}

/// rustls clock backed by our [`Clock`], so tests can move time.
#[derive(Debug)]
struct ClockTime(Arc<dyn Clock>);

impl TimeProvider for ClockTime {
    fn current_time(&self) -> Option<PkiTime> {
        Some(PkiTime::since_unix_epoch(Duration::from_secs(
            self.0.now().secs(),
        )))
    }
}

/// Our session key as a rustls signing key. Signing goes through core, so
/// the private key never leaves its zeroizing container.
struct SessionSigningKey(Arc<SessionKey>);

impl fmt::Debug for SessionSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSigningKey(..)")
    }
}

impl SigningKey for SessionSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SCHEME)
            .then(|| Box::new(SessionSigner(self.0.clone())) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

struct SessionSigner(Arc<SessionKey>);

impl fmt::Debug for SessionSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSigner(..)")
    }
}

impl Signer for SessionSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.sign_tls(message))
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

fn certified_key(cert: &SessionCertificate) -> Arc<CertifiedKey> {
    Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(cert.der().to_vec())],
        Arc::new(SessionSigningKey(Arc::new(cert.key().clone()))),
    ))
}

#[derive(Debug)]
struct OwnCert(Arc<CertifiedKey>);

impl ResolvesClientCert for OwnCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        sigschemes.contains(&SCHEME).then(|| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ResolvesServerCert for OwnCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn cert_error(e: CertError) -> Error {
    Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
}

/// Check a `CertificateVerify` signature with the session key of `cert`.
fn verify_cert_verify(
    clock: &dyn Clock,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme != SCHEME {
        return Err(Error::PeerMisbehaved(
            rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    let verified = session_cert::verify(cert.as_ref(), clock.now(), None).map_err(cert_error)?;
    verified
        .verify_tls_signature(message, dss.signature())
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadSignature))?;
    Ok(HandshakeSignatureValid::assertion())
}

/// The pin to enforce. The `skip-pin-check` control build (tests only)
/// drops it, so any valid certificate passes.
fn checked_pin(pin: &IdentityPublicKey) -> Option<&IdentityPublicKey> {
    if cfg!(mousse_control = "skip-pin-check") {
        None
    } else {
        Some(pin)
    }
}

/// Caller side: the host must be the pinned identity.
#[derive(Debug)]
struct PinnedHostVerifier {
    pin: IdentityPublicKey,
    clock: Arc<dyn Clock>,
}

impl ServerCertVerifier for PinnedHostVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: PkiTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(cert_error(CertError::Malformed));
        }
        session_cert::verify(
            end_entity.as_ref(),
            self.clock.now(),
            checked_pin(&self.pin),
        )
        .map_err(cert_error)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_cert_verify(&*self.clock, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}

/// Host side: any valid session certificate; step 2 decides afterwards.
#[derive(Debug)]
struct AnyDeviceVerifier {
    clock: Arc<dyn Clock>,
}

impl ClientCertVerifier for AnyDeviceVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: PkiTime,
    ) -> Result<ClientCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(cert_error(CertError::Malformed));
        }
        session_cert::verify(end_entity.as_ref(), self.clock.now(), None).map_err(cert_error)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_cert_verify(&*self.clock, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}

/// Client configuration for one connection to the host pinned as `pin`.
pub fn client_config(
    own: &SessionCertificate,
    pin: IdentityPublicKey,
    clock: Arc<dyn Clock>,
) -> Result<Arc<ClientConfig>, NetError> {
    let mut config =
        ClientConfig::builder_with_details(provider(), Arc::new(ClockTime(clock.clone())))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| NetError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedHostVerifier { pin, clock }))
            .with_client_cert_resolver(Arc::new(OwnCert(certified_key(own))));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_sni = false;
    Ok(Arc::new(config))
}

/// Server configuration for accepting one connection.
pub fn server_config(
    own: &SessionCertificate,
    clock: Arc<dyn Clock>,
) -> Result<Arc<ServerConfig>, NetError> {
    let mut config =
        ServerConfig::builder_with_details(provider(), Arc::new(ClockTime(clock.clone())))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| NetError::Tls(e.to_string()))?
            .with_client_cert_verifier(Arc::new(AnyDeviceVerifier { clock }))
            .with_cert_resolver(Arc::new(OwnCert(certified_key(own))));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

/// What step 1 established.
#[derive(Clone, Debug)]
pub struct Handshake {
    /// The peer's verified certificate (identity, window).
    pub peer: VerifiedSessionCert,
    /// Our own certificate's window on this connection.
    pub local_window: ValidityWindow,
    /// Exporters of this peer session, for pairing.
    pub exporters: SessionExporters,
    /// The negotiated key exchange group, for diagnostics.
    pub kx_group: String,
}

/// Turn a handshake failure into an error that keeps our verifier's reason.
fn map_handshake_error(e: std::io::Error) -> NetError {
    if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<Error>()) {
        if let Error::InvalidCertificate(CertificateError::Other(other)) = inner {
            if let Some(cert) = other.0.downcast_ref::<CertError>() {
                return NetError::PeerCertificate(*cert);
            }
        }
        return NetError::Tls(inner.to_string());
    }
    NetError::Io(e)
}

fn exporters(
    export: impl Fn(&str) -> Result<[u8; 32], Error>,
) -> Result<SessionExporters, NetError> {
    let join = export(JOIN_EXPORTER_LABEL).map_err(|e| NetError::Tls(e.to_string()))?;
    let pair = export(PAIR_EXPORTER_LABEL).map_err(|e| NetError::Tls(e.to_string()))?;
    Ok(SessionExporters { join, pair })
}

fn finish(
    common: &CommonState,
    exporters: SessionExporters,
    clock: &dyn Clock,
    pin: Option<&IdentityPublicKey>,
    local_window: ValidityWindow,
    policy: TlsPolicy,
) -> Result<Handshake, NetError> {
    if common.alpn_protocol() != Some(ALPN) {
        return Err(NetError::Tls("ALPN mousse/1 was not negotiated".into()));
    }
    let group = common
        .negotiated_key_exchange_group()
        .map(|g| g.name())
        .ok_or_else(|| NetError::Tls("no key exchange group".into()))?;
    if policy.require_hybrid && group != NamedGroup::X25519MLKEM768 {
        return Err(NetError::Tls(format!(
            "key exchange {group:?} is not the hybrid group"
        )));
    }
    let der = common
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| NetError::Tls("peer sent no certificate".into()))?;
    let peer = session_cert::verify(der.as_ref(), clock.now(), pin.and_then(checked_pin))
        .map_err(NetError::PeerCertificate)?;
    Ok(Handshake {
        peer,
        local_window,
        exporters,
        kx_group: format!("{group:?}"),
    })
}

/// Run the caller side of step 1 over `pipe`, pinning the host to `pin`.
pub async fn connect<P: Pipe>(
    pipe: P,
    own: &SessionCertificate,
    pin: IdentityPublicKey,
    clock: Arc<dyn Clock>,
    policy: TlsPolicy,
) -> Result<(TlsStream<P>, Handshake), NetError> {
    let config = client_config(own, pin, clock.clone())?;
    let name = ServerName::try_from("mousse-session").map_err(|e| NetError::Tls(e.to_string()))?;
    let stream = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsConnector::from(config).connect(name, pipe),
    )
    .await
    .map_err(|_| NetError::Timeout("TLS handshake"))?
    .map_err(map_handshake_error)?;
    let conn = stream.get_ref().1;
    let exporters =
        exporters(|label| conn.export_keying_material([0u8; 32], label.as_bytes(), None))?;
    let handshake = finish(conn, exporters, &*clock, Some(&pin), own.window(), policy)?;
    Ok((TlsStream::Client(stream), handshake))
}

/// Run the host side of step 1 over `pipe`. Any valid device certificate is
/// accepted here; step 2 runs next.
pub async fn accept<P: Pipe>(
    pipe: P,
    own: &SessionCertificate,
    clock: Arc<dyn Clock>,
    policy: TlsPolicy,
) -> Result<(TlsStream<P>, Handshake), NetError> {
    let config = server_config(own, clock.clone())?;
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, TlsAcceptor::from(config).accept(pipe))
        .await
        .map_err(|_| NetError::Timeout("TLS handshake"))?
        .map_err(map_handshake_error)?;
    let conn = stream.get_ref().1;
    let exporters =
        exporters(|label| conn.export_keying_material([0u8; 32], label.as_bytes(), None))?;
    let handshake = finish(conn, exporters, &*clock, None, own.window(), policy)?;
    Ok((TlsStream::Server(stream), handshake))
}
