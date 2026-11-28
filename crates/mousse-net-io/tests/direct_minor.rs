//! Pair with IP's messages are defined only from minor 4. This build agrees
//! minor 3, so a peer that sends one anyway is closed for a protocol error
//! before its role sees it.

mod common;

use std::sync::Arc;

use common::*;
use mousse_net_core::control::{ControlMessage, VersionSupport, DIRECT_MINOR_VERSION};
use mousse_net_core::mux::{Mux, MuxEvent, MuxRole};
use mousse_net_core::pairing::DirectLookup;
use mousse_net_core::ErrorCode;
use mousse_net_io::certs::CertManager;
use mousse_net_io::{tls, Clock, ManualClock, TlsPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// This build still speaks minor 3; raising the minor to 4 changes this test.
const _: () = assert!(VersionSupport::LOCAL.minor < DIRECT_MINOR_VERSION);

#[tokio::test(start_paused = true)]
async fn a_join_direct_on_a_minor_3_connection_is_a_protocol_error() {
    let host = TestHost::start(new_signer()).await;
    let clock = Arc::new(ManualClock::new());
    let cert = CertManager::new(new_signer(), clock.clone())
        .current()
        .unwrap();
    let (hosts, callers) = tokio::io::duplex(1 << 16);
    let accepting = host.host.clone();
    let accept = tokio::spawn(async move { accepting.accept(hosts).await });
    let (stream, _) = tls::connect(
        callers,
        &cert,
        host.identity(),
        clock.clone(),
        TlsPolicy::default(),
    )
    .await
    .unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut mux = Mux::new(MuxRole::Caller, clock.mono());
    // A peer that claims minor 4: the connection still agrees minor 3.
    let hello = ControlMessage::Hello {
        major_version: VersionSupport::LOCAL.major,
        minor_version: DIRECT_MINOR_VERSION,
    };
    mux.send_control(hello.encode()).unwrap();
    let mut sent = false;
    let mut buf = vec![0u8; 16 * 1024];
    let code = 'read: loop {
        while let Some(frame) = mux.poll_transmit(clock.mono()) {
            wr.write_all(&frame).await.unwrap();
        }
        wr.flush().await.unwrap();
        let n = within("host frames", rd.read(&mut buf)).await.unwrap();
        assert!(n > 0, "the host hung up without a GOAWAY");
        for event in mux.receive(&buf[..n], clock.mono()).unwrap() {
            match event {
                // The host's HELLO: the version is agreed.
                MuxEvent::Control(_) if !sent => {
                    sent = true;
                    let join = ControlMessage::JoinDirect {
                        lookup: DirectLookup::from_canonical("K7QM").unwrap(),
                        name: "laptop".into(),
                        recovery: None,
                    };
                    mux.send_control(join.encode()).unwrap();
                }
                MuxEvent::GoAway { code } => break 'read code,
                _ => {}
            }
        }
    };
    accept.abort();
    assert_eq!(code, ErrorCode::ProtocolError);
    host.stop().await;
}
