//! Verifiers that accept exactly one pinned peer key and ignore chains.
//!
//! The pin is the DER SubjectPublicKeyInfo of the peer's certificate key. The
//! certificate's issuer, names, dates and any intermediates are not checked;
//! the TLS 1.3 CertificateVerify signature is, with the pinned key, so a peer
//! that merely replays the certificate cannot finish the handshake.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

/// The only signature scheme the session accepts.
pub const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

fn check_pin(end_entity: &CertificateDer<'_>, pin: &[u8]) -> Result<(), Error> {
    let parsed = ParsedCertificate::try_from(end_entity)?;
    let spki = parsed.subject_public_key_info();
    if spki.as_ref() == pin {
        Ok(())
    } else {
        Err(Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }
}

fn tls12_refused() -> Result<HandshakeSignatureValid, Error> {
    Err(Error::General("TLS 1.2 is not allowed".into()))
}

/// Client side: checks the server's key.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    pin: Vec<u8>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    pub fn new(pin: Vec<u8>, algs: WebPkiSupportedAlgorithms) -> Self {
        Self { pin, algs }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        check_pin(end_entity, &self.pin)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls12_refused()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}

/// Server side: client authentication is mandatory and checks the client's key.
#[derive(Debug)]
pub struct PinnedClientVerifier {
    pin: Vec<u8>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedClientVerifier {
    pub fn new(pin: Vec<u8>, algs: WebPkiSupportedAlgorithms) -> Self {
        Self { pin, algs }
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
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
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        check_pin(end_entity, &self.pin)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls12_refused()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}
