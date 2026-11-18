//! The same handshake over a real TCP loopback socket (native only).

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ClientConnection, Connection, Error, ServerConnection, StreamOwned};

use crate::handshake::{io_error, server_name, Established, Outcome, Refused, Setup, SideView};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn set_timeouts(sock: &TcpStream) -> Result<(), Error> {
    sock.set_read_timeout(Some(IO_TIMEOUT)).map_err(io_error)?;
    sock.set_write_timeout(Some(IO_TIMEOUT)).map_err(io_error)?;
    Ok(())
}

fn serve(
    listener: TcpListener,
    setup_server: std::sync::Arc<rustls::ServerConfig>,
) -> Result<SideView, Error> {
    // Poll so a client that never connects cannot leave this thread waiting.
    listener.set_nonblocking(true).map_err(io_error)?;
    let deadline = Instant::now() + IO_TIMEOUT;
    let sock = loop {
        match listener.accept() {
            Ok((sock, _)) => break sock,
            Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(io_error(e)),
        }
    };
    sock.set_nonblocking(false).map_err(io_error)?;
    set_timeouts(&sock)?;
    let mut tls = StreamOwned::new(ServerConnection::new(setup_server)?, sock);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(io_error)?;
    }
    let mut ping = [0u8; 4];
    tls.read_exact(&mut ping).map_err(io_error)?;
    if &ping != b"ping" {
        return Err(Error::General("server did not read ping".into()));
    }
    tls.write_all(b"pong").map_err(io_error)?;
    tls.flush().map_err(io_error)?;
    let StreamOwned { conn, sock } = tls;
    let conn = Connection::Server(conn);
    let view = SideView::of(&conn);
    drop(sock);
    view
}

fn dial(addr: std::net::SocketAddr, setup: &Setup) -> Result<SideView, Error> {
    let sock = TcpStream::connect(addr).map_err(io_error)?;
    set_timeouts(&sock)?;
    let mut tls = StreamOwned::new(
        ClientConnection::new(setup.client.clone(), server_name())?,
        sock,
    );
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(io_error)?;
    }
    tls.write_all(b"ping").map_err(io_error)?;
    tls.flush().map_err(io_error)?;
    let mut pong = [0u8; 4];
    tls.read_exact(&mut pong).map_err(io_error)?;
    if &pong != b"pong" {
        return Err(Error::General("client did not read pong".into()));
    }
    let StreamOwned { conn, sock } = tls;
    let conn = Connection::Client(conn);
    let view = SideView::of(&conn);
    drop(sock);
    view
}

/// Runs one handshake plus a ping/pong over TCP on 127.0.0.1. The server runs
/// on its own thread and both sockets have timeouts, so nothing is left behind.
pub fn run_tcp(setup: &Setup) -> Outcome {
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            return Err(Box::new(Refused {
                client: None,
                server: Some(io_error(e)),
            }))
        }
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => {
            return Err(Box::new(Refused {
                client: None,
                server: Some(io_error(e)),
            }))
        }
    };
    let server_cfg = setup.server.clone();
    let server = thread::spawn(move || serve(listener, server_cfg));
    let client = dial(addr, setup);
    let server = server
        .join()
        .unwrap_or_else(|_| Err(Error::General("server thread panicked".into())));

    match (client, server) {
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
