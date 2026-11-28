//! A host whose oldest minor is above the caller's newest says `HELLO` and
//! `AUTHORIZED` before it has read the caller's `HELLO` (wire.md 2 and 8).
//! The caller must not go live on that connection: the host refuses it as
//! soon as it reads the caller's `HELLO`. The dial ends with the host's
//! version instead, and the host sees the caller's `HELLO` once, then
//! `GOAWAY(UNSUPPORTED_VERSION)`.
//!
//! On this single-threaded runtime the host's frames are waiting when the
//! caller's driver first runs, so it reads them before its writer takes
//! its own queued `HELLO`: the close must not drop that `HELLO`.

mod common;

use std::sync::Arc;

use common::*;
use mousse_net_core::control::{AuthorizedState, ControlMessage, VersionSupport};
use mousse_net_core::mux::{Mux, MuxEvent, MuxRole};
use mousse_net_core::ErrorCode;
use mousse_net_io::certs::CertManager;
use mousse_net_io::{tls, Clock, CloseReason, ManualClock, NetError, TlsPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn a_caller_below_the_hosts_oldest_minor_never_goes_live() {
    let clock = Arc::new(ManualClock::new());
    let cert = CertManager::new(new_signer(), clock.clone())
        .current()
        .unwrap();
    let identity = *cert.identity();
    let (hosts, callers) = tokio::io::duplex(1 << 16);
    // Two minors ahead of the caller: its oldest is above the caller's newest.
    let newer = VersionSupport::LOCAL.minor + 2;
    let host_clock = clock.clone();
    let host = tokio::spawn(async move {
        let (stream, _) = tls::accept(hosts, &cert, host_clock.clone(), TlsPolicy::default())
            .await
            .unwrap();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut mux = Mux::new(MuxRole::Host, host_clock.mono());
        let hello = ControlMessage::Hello {
            major_version: VersionSupport::LOCAL.major,
            minor_version: newer,
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
        // Never answers: only records what the caller sends until it
        // hangs up.
        let mut seen = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n @ 1..) = rd.read(&mut buf).await {
            let Ok(events) = mux.receive(&buf[..n], host_clock.mono()) else {
                break;
            };
            for event in events {
                match event {
                    MuxEvent::Control(bytes) => seen.push(match ControlMessage::decode(&bytes) {
                        Ok(ControlMessage::Hello { minor_version, .. }) => {
                            format!("hello {minor_version}")
                        }
                        Ok(_) => "another control message".to_string(),
                        Err(_) => "undecodable control".to_string(),
                    }),
                    MuxEvent::GoAway { code } => seen.push(format!("goaway {}", code.name())),
                    _ => {}
                }
            }
        }
        seen
    });

    let caller = new_caller_with_clock(new_signer(), clock);
    let dialled = within("the dial", caller.dial(callers, identity)).await;
    match dialled {
        Err(NetError::Version { reason, peer_minor }) => {
            assert_eq!(peer_minor, newer);
            assert_eq!(
                reason,
                CloseReason::Local(ErrorCode::UnsupportedVersion),
                "{reason}"
            );
        }
        Err(e) => panic!("expected a refusal for version, got {e}"),
        Ok(_) => panic!("the caller went live on a connection the host refuses"),
    }
    let seen = within("the host's record", host).await.unwrap();
    assert_eq!(
        seen,
        [
            format!("hello {}", VersionSupport::LOCAL.minor),
            "goaway unsupported_version".to_string(),
        ]
    );
}
