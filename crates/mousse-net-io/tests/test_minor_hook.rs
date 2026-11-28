//! In a debug build, `MOUSSE_NET_TEST_HELLO_MINOR=4` makes a connection
//! speak the Pair with IP minor before the build's own minor reaches it:
//! the caller advertises minor 4 in its `HELLO` and agrees minor 4 with a
//! host that speaks it. Release builds ignore the variable.
//!
//! The variable is process wide, so this binary holds this one test only.
#![cfg(debug_assertions)]

mod common;

use std::sync::Arc;

use common::*;
use mousse_net_core::control::{
    AuthorizedState, ControlMessage, VersionSupport, DIRECT_MINOR_VERSION,
};
use mousse_net_core::mux::{Mux, MuxEvent, MuxRole};
use mousse_net_core::ErrorCode;
use mousse_net_io::certs::CertManager;
use mousse_net_io::conn::TEST_HELLO_MINOR_VAR;
use mousse_net_io::{tls, Clock, ManualClock, TlsPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// The override only matters while the build's own minor is older.
const _: () = assert!(VersionSupport::LOCAL.minor < DIRECT_MINOR_VERSION);

#[tokio::test]
async fn the_override_advertises_and_agrees_the_pair_with_ip_minor() {
    std::env::set_var(TEST_HELLO_MINOR_VAR, DIRECT_MINOR_VERSION.to_string());
    let clock = Arc::new(ManualClock::new());
    let cert = CertManager::new(new_signer(), clock.clone())
        .current()
        .unwrap();
    let identity = *cert.identity();
    let (hosts, callers) = tokio::io::duplex(1 << 16);
    let host_clock = clock.clone();
    // A host that speaks minor 4 and grants the caller; it records the
    // minor of the caller's HELLO and stays up until the caller hangs up.
    let host = tokio::spawn(async move {
        let (stream, _) = tls::accept(hosts, &cert, host_clock.clone(), TlsPolicy::default())
            .await
            .unwrap();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut mux = Mux::new(MuxRole::Host, host_clock.mono());
        let hello = ControlMessage::Hello {
            major_version: VersionSupport::LOCAL.major,
            minor_version: DIRECT_MINOR_VERSION,
        };
        mux.send_control(hello.encode()).unwrap();
        let authorized = ControlMessage::Authorized {
            state: AuthorizedState::Live,
        };
        mux.send_control(authorized.encode()).unwrap();
        while let Some(frame) = mux.poll_transmit(host_clock.mono()) {
            wr.write_all(&frame).await.unwrap();
        }
        wr.flush().await.unwrap();
        let mut advertised = None;
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n @ 1..) = rd.read(&mut buf).await {
            let Ok(events) = mux.receive(&buf[..n], host_clock.mono()) else {
                break;
            };
            for event in events {
                if let MuxEvent::Control(bytes) = event {
                    if let Ok(ControlMessage::Hello { minor_version, .. }) =
                        ControlMessage::decode(&bytes)
                    {
                        advertised.get_or_insert(minor_version);
                    }
                }
            }
        }
        advertised
    });

    let caller = new_caller_with_clock(new_signer(), clock);
    let conn = within("the dial", caller.dial(callers, identity))
        .await
        .expect("the caller goes live");
    assert_eq!(
        within("the agreed minor", conn.hello_minor()).await,
        Some(DIRECT_MINOR_VERSION),
        "both sides speak minor 4, so they agree it"
    );
    conn.close(ErrorCode::NoError);
    assert_eq!(
        within("the caller's HELLO", host).await.unwrap(),
        Some(DIRECT_MINOR_VERSION),
        "the caller advertises the overridden minor"
    );
}
