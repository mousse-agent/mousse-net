//! Mutual TLS 1.3 between two devices on session certificates (step 1).
//!
//! - TLS 1.3 only, mandatory client certificates, ALPN `mousse/1`.
//! - The only signature scheme is `ecdsa_secp256r1_sha256`.
//! - Both verifiers call [`session_cert::verify`]. The caller passes the
//!   stored pin (or, on first contact, the ticket's host identity) on every
//!   connection. The host passes no pin; step 2 decides what the peer may do.
//! - No session resumption, no tickets, no PSK and no early data, so every
//!   connection runs a full handshake and the verifier again.
//! - Key exchange offers X25519MLKEM768 first and X25519 second (aws-lc-rs),
//!   and a connection that did not negotiate X25519MLKEM768 is closed
//!   before any application data (wire.md 5.4).

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
use crate::limits::{ms, Limits};
use crate::pipe::Pipe;

/// The only `CertificateVerify` scheme peers use.
pub const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

/// The TLS policy. Wire.md 5.4 makes the protocol choices requirements, so
/// the only settings are two limits: the clock skew the verifiers allow and
/// how long a handshake may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsPolicy {
    skew_secs: u64,
    handshake_timeout: Duration,
}

impl TlsPolicy {
    /// The policy for `limits`.
    pub fn from_limits(limits: &Limits) -> Self {
        Self {
            skew_secs: limits.core.clock_skew_secs,
            handshake_timeout: ms(limits.io.handshake_timeout_ms),
        }
    }
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self::from_limits(&Limits::DEFAULT)
    }
}

/// The groups a native endpoint offers, in order.
pub const KX_GROUPS: [NamedGroup; 2] = [NamedGroup::X25519MLKEM768, NamedGroup::X25519];

/// The aws-lc-rs provider offering exactly [`KX_GROUPS`], in that order.
pub fn provider() -> Arc<CryptoProvider> {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    let all = std::mem::take(&mut p.kx_groups);
    p.kx_groups = KX_GROUPS
        .iter()
        .filter_map(|name| all.iter().find(|g| g.name() == *name).copied())
        .collect();
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
    skew_secs: u64,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme != SCHEME {
        return Err(Error::PeerMisbehaved(
            rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    let verified = session_cert::verify_with_skew(cert.as_ref(), clock.now(), None, skew_secs)
        .map_err(cert_error)?;
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
    skew_secs: u64,
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
        session_cert::verify_with_skew(
            end_entity.as_ref(),
            self.clock.now(),
            checked_pin(&self.pin),
            self.skew_secs,
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
        verify_cert_verify(&*self.clock, self.skew_secs, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}

/// Host side: any valid session certificate; step 2 decides afterwards.
#[derive(Debug)]
struct AnyDeviceVerifier {
    clock: Arc<dyn Clock>,
    skew_secs: u64,
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
        session_cert::verify_with_skew(end_entity.as_ref(), self.clock.now(), None, self.skew_secs)
            .map_err(cert_error)?;
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
        verify_cert_verify(&*self.clock, self.skew_secs, message, cert, dss)
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
    policy: TlsPolicy,
) -> Result<Arc<ClientConfig>, NetError> {
    client_config_on(provider(), own, pin, clock, policy)
}

fn client_config_on(
    provider: Arc<CryptoProvider>,
    own: &SessionCertificate,
    pin: IdentityPublicKey,
    clock: Arc<dyn Clock>,
    policy: TlsPolicy,
) -> Result<Arc<ClientConfig>, NetError> {
    let mut config =
        ClientConfig::builder_with_details(provider, Arc::new(ClockTime(clock.clone())))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| NetError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedHostVerifier {
                pin,
                clock,
                skew_secs: policy.skew_secs,
            }))
            .with_client_cert_resolver(Arc::new(OwnCert(certified_key(own))));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
    Ok(Arc::new(config))
}

/// Server configuration for accepting one connection.
pub fn server_config(
    own: &SessionCertificate,
    clock: Arc<dyn Clock>,
    policy: TlsPolicy,
) -> Result<Arc<ServerConfig>, NetError> {
    let mut config =
        ServerConfig::builder_with_details(provider(), Arc::new(ClockTime(clock.clone())))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| NetError::Tls(e.to_string()))?
            .with_client_cert_verifier(Arc::new(AnyDeviceVerifier {
                clock,
                skew_secs: policy.skew_secs,
            }))
            .with_cert_resolver(Arc::new(OwnCert(certified_key(own))));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
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
    if group != NamedGroup::X25519MLKEM768 {
        return Err(NetError::Tls(format!(
            "key exchange {group:?} is not the hybrid group"
        )));
    }
    let der = common
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| NetError::Tls("peer sent no certificate".into()))?;
    let peer = session_cert::verify_with_skew(
        der.as_ref(),
        clock.now(),
        pin.and_then(checked_pin),
        policy.skew_secs,
    )
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
    let config = client_config(own, pin, clock.clone(), policy)?;
    let name = ServerName::try_from("mousse-session").map_err(|e| NetError::Tls(e.to_string()))?;
    let stream = tokio::time::timeout(
        policy.handshake_timeout,
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
    let config = server_config(own, clock.clone(), policy)?;
    let stream = tokio::time::timeout(
        policy.handshake_timeout,
        TlsAcceptor::from(config).accept(pipe),
    )
    .await
    .map_err(|_| NetError::Timeout("TLS handshake"))?
    .map_err(map_handshake_error)?;
    let conn = stream.get_ref().1;
    let exporters =
        exporters(|label| conn.export_keying_material([0u8; 32], label.as_bytes(), None))?;
    let handshake = finish(conn, exporters, &*clock, None, own.window(), policy)?;
    Ok((TlsStream::Server(stream), handshake))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::CertManager;
    use crate::clock::ManualClock;
    use crate::rng::os_rng;
    use mousse_net_core::identity::SoftwareKey;

    fn cert(clock: Arc<ManualClock>) -> SessionCertificate {
        CertManager::new(Arc::new(SoftwareKey::generate(&mut os_rng())), clock)
            .current()
            .unwrap()
    }

    #[test]
    fn a_native_endpoint_offers_the_hybrid_group_then_x25519_and_no_other() {
        let names: Vec<NamedGroup> = provider().kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(names, KX_GROUPS.to_vec());
    }

    /// A caller that offers X25519 alone completes the TLS handshake, and
    /// the host closes it before any application data.
    #[tokio::test]
    async fn a_connection_without_the_hybrid_group_is_refused() {
        let clock = Arc::new(ManualClock::new());
        let (caller, host) = (cert(clock.clone()), cert(clock.clone()));
        let mut classical = rustls::crypto::aws_lc_rs::default_provider();
        classical
            .kx_groups
            .retain(|g| g.name() == NamedGroup::X25519);
        let config = client_config_on(
            Arc::new(classical),
            &caller,
            *host.identity(),
            clock.clone(),
            TlsPolicy::default(),
        )
        .unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        let name = ServerName::try_from("mousse-session").unwrap();
        let (dialled, accepted) = tokio::join!(
            TlsConnector::from(config).connect(name, a),
            accept(b, &host, clock.clone(), TlsPolicy::default()),
        );
        let dialled = dialled.unwrap();
        assert_eq!(
            dialled
                .get_ref()
                .1
                .negotiated_key_exchange_group()
                .map(|g| g.name()),
            Some(NamedGroup::X25519)
        );
        match accepted {
            Err(NetError::Tls(e)) => assert!(e.contains("hybrid"), "{e}"),
            other => panic!("accepted a classical-only connection: {:?}", other.err()),
        }
    }
}
