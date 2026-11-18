//! Endpoint configuration for each case, and the in-memory pipe transport.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, Connection, Error, ServerConfig, ServerConnection};

use crate::certs::{self, Identity};
use crate::provider::{FixedClock, Provider};
use crate::verify::{PinnedClientVerifier, PinnedServerVerifier};

/// One handshake scenario. Every case except `Mutual` must be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    /// Both sides present the pinned key. Must succeed.
    Mutual,
    /// The client pins a key the server does not hold.
    WrongServerPin,
    /// The server pins a key the client does not hold.
    WrongClientPin,
    /// The client sends no certificate.
    MissingClientCert,
    /// The client offers TLS 1.2 only.
    Tls12Only,
}

impl Case {
    pub const ALL: [Case; 5] = [
        Case::Mutual,
        Case::WrongServerPin,
        Case::WrongClientPin,
        Case::MissingClientCert,
        Case::Tls12Only,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Case::Mutual => "mutual",
            Case::WrongServerPin => "wrong-server-pin",
            Case::WrongClientPin => "wrong-client-pin",
            Case::MissingClientCert => "missing-client-cert",
            Case::Tls12Only => "tls12-only",
        }
    }
}

/// Client and server configurations for one case.
pub struct Setup {
    pub client: Arc<ClientConfig>,
    pub server: Arc<ServerConfig>,
}

/// Inputs shared by every case in a run.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub client: Provider,
    pub server: Provider,
    pub now_unix_secs: u64,
    /// Deliberately broken mode: the client pins the wrong server key even in
    /// the `Mutual` case, so a correct run must report FAIL.
    pub break_pin: bool,
}

pub fn server_name() -> ServerName<'static> {
    ServerName::try_from("mousse-session").expect("static name is valid")
}

fn provider_or_err(p: Provider) -> Result<Arc<rustls::crypto::CryptoProvider>, String> {
    p.crypto_provider()
        .ok_or_else(|| format!("provider {} is not compiled in", p.name()))
}

/// Builds fresh keys and both configurations for `case`.
pub fn build(case: Case, params: Params) -> Result<Setup, String> {
    let client_id: Identity = certs::generate("mousse-client").map_err(|e| e.to_string())?;
    let server_id: Identity = certs::generate("mousse-session").map_err(|e| e.to_string())?;
    let stranger: Identity = certs::generate("mousse-stranger").map_err(|e| e.to_string())?;

    let cp = provider_or_err(params.client)?;
    let sp = provider_or_err(params.server)?;
    let clock = FixedClock::at_unix_secs(params.now_unix_secs);

    let swap_server_pin =
        case == Case::WrongServerPin || (case == Case::Mutual && params.break_pin);
    let pinned_server = if swap_server_pin {
        stranger.spki.clone()
    } else {
        server_id.spki.clone()
    };
    let pinned_client = if case == Case::WrongClientPin {
        stranger.spki.clone()
    } else {
        client_id.spki.clone()
    };

    let client_versions: &[&rustls::SupportedProtocolVersion] = if case == Case::Tls12Only {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };

    let algs = cp.signature_verification_algorithms;
    let builder = ClientConfig::builder_with_details(cp.clone(), clock.clone())
        .with_protocol_versions(client_versions)
        .map_err(|e| format!("client config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(pinned_server, algs)));
    let client = if case == Case::MissingClientCert {
        builder.with_no_client_auth()
    } else {
        builder
            .with_client_auth_cert(vec![client_id.cert.clone()], client_id.key_der())
            .map_err(|e| format!("client cert: {e}"))?
    };

    let server = ServerConfig::builder_with_details(sp.clone(), clock)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("server config: {e}"))?
        .with_client_cert_verifier(Arc::new(PinnedClientVerifier::new(
            pinned_client,
            sp.signature_verification_algorithms,
        )))
        .with_single_cert(vec![server_id.cert.clone()], server_id.key_der())
        .map_err(|e| format!("server cert: {e}"))?;

    Ok(Setup {
        client: Arc::new(client),
        server: Arc::new(server),
    })
}

/// What one side saw after a completed handshake. The exporter value is
/// compared between sides and runs, never printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SideView {
    pub kx_group: String,
    pub suite: String,
    pub version: String,
    pub kind: String,
    pub exporter: Vec<u8>,
}

impl SideView {
    pub fn of(conn: &Connection) -> Result<SideView, Error> {
        let exporter = conn.export_keying_material(
            [0u8; 32],
            crate::EXPORTER_LABEL,
            Some(crate::EXPORTER_CONTEXT),
        )?;
        Ok(SideView {
            kx_group: conn
                .negotiated_key_exchange_group()
                .map(|g| format!("{:?}", g.name()))
                .unwrap_or_default(),
            suite: conn
                .negotiated_cipher_suite()
                .map(|s| format!("{:?}", s.suite()))
                .unwrap_or_default(),
            version: conn
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_default(),
            kind: conn
                .handshake_kind()
                .map(|k| format!("{k:?}"))
                .unwrap_or_default(),
            exporter: exporter.to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Established {
    pub client: SideView,
    pub server: SideView,
}

/// A refused handshake: the first error each side reported, if any.
#[derive(Clone, Debug, Default)]
pub struct Refused {
    pub client: Option<Error>,
    pub server: Option<Error>,
}

pub type Outcome = Result<Established, Box<Refused>>;

pub(crate) fn io_error(e: std::io::Error) -> Error {
    match e.get_ref().and_then(|inner| inner.downcast_ref::<Error>()) {
        Some(tls) => tls.clone(),
        None => Error::General(format!("io: {e}")),
    }
}

/// Moves every pending TLS record from `from` to `to`. Returns the byte count.
fn transfer(from: &mut Connection, to: &mut Connection) -> Result<usize, Error> {
    let mut total = 0;
    while from.wants_write() {
        let mut buf = Vec::new();
        let n = from.write_tls(&mut buf).map_err(io_error)?;
        if n == 0 {
            break;
        }
        let mut rest: &[u8] = &buf;
        while !rest.is_empty() {
            if to.read_tls(&mut rest).map_err(io_error)? == 0 {
                break;
            }
        }
        total += n;
    }
    Ok(total)
}

fn record(slot: &mut Option<Error>, result: Result<(), Error>) {
    if let Err(e) = result {
        if slot.is_none() {
            *slot = Some(e);
        }
    }
}

/// Drives both ends until no bytes move. Errors are kept, not returned, so
/// the peer still receives the alert and its own view is recorded.
fn pump(client: &mut Connection, server: &mut Connection, refused: &mut Refused) {
    for _ in 0..64 {
        let moved_a = match transfer(client, server) {
            Ok(n) => n,
            Err(e) => {
                record(&mut refused.server, Err(e));
                0
            }
        };
        if moved_a > 0 {
            record(
                &mut refused.server,
                server.process_new_packets().map(|_| ()),
            );
        }
        let moved_b = match transfer(server, client) {
            Ok(n) => n,
            Err(e) => {
                record(&mut refused.client, Err(e));
                0
            }
        };
        if moved_b > 0 {
            record(
                &mut refused.client,
                client.process_new_packets().map(|_| ()),
            );
        }
        if moved_a == 0 && moved_b == 0 {
            break;
        }
    }
}

fn read_all(conn: &mut Connection) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match conn.reader().read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

/// Runs one handshake over an in-memory pipe, then one round trip of
/// application data so a late refusal (the server checks the client's
/// certificate after the client already considers itself done) is seen.
pub fn run_pipe(setup: &Setup) -> Outcome {
    let mut refused = Refused::default();
    let client = ClientConnection::new(setup.client.clone(), server_name());
    let server = ServerConnection::new(setup.server.clone());
    let (mut client, mut server) = match (client, server) {
        (Ok(c), Ok(s)) => (Connection::Client(c), Connection::Server(s)),
        (c, s) => {
            refused.client = c.err();
            refused.server = s.err();
            return Err(Box::new(refused));
        }
    };

    pump(&mut client, &mut server, &mut refused);
    if refused.client.is_none() && refused.server.is_none() {
        record(
            &mut refused.client,
            client.writer().write_all(b"ping").map_err(io_error),
        );
        pump(&mut client, &mut server, &mut refused);
        if refused.server.is_none() && read_all(&mut server) != b"ping" {
            refused.server = Some(Error::General("server did not read ping".into()));
        }
        record(
            &mut refused.server,
            server.writer().write_all(b"pong").map_err(io_error),
        );
        pump(&mut client, &mut server, &mut refused);
        if refused.client.is_none() && read_all(&mut client) != b"pong" {
            refused.client = Some(Error::General("client did not read pong".into()));
        }
    }

    if refused.client.is_some() || refused.server.is_some() {
        return Err(Box::new(refused));
    }
    if client.is_handshaking() || server.is_handshaking() {
        refused.client = Some(Error::General("handshake did not finish".into()));
        return Err(Box::new(refused));
    }
    match (SideView::of(&client), SideView::of(&server)) {
        (Ok(c), Ok(s)) => Ok(Established {
            client: c,
            server: s,
        }),
        (c, s) => Err(Box::new(Refused {
            client: c.err(),
            server: s.err(),
        })),
    }
}
