//! Host checks of the same API the phone apps drive. Futures are polled by a plain
//! executor (as Swift and Kotlin do), never inside a tokio context.

use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use futures_executor::block_on;
use mousse_phone_spike::*;

const UNROUTABLE: &str = "10.255.255.1:9";

fn engine(break_mode: Option<&str>) -> Arc<Engine> {
    Engine::new(EngineConfig {
        event_capacity: 16,
        worker_threads: 2,
        break_mode: break_mode.map(str::to_string),
    })
}

fn settle(mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(500) {
        if f() {
            return true;
        }
        sleep(Duration::from_millis(5));
    }
    f()
}

#[test]
fn lifecycle_dial_cancel_stop_leaves_nothing() {
    let sockets0 = open_socket_fds();
    let e = engine(None);
    e.start().unwrap();
    assert_eq!(e.start(), Err(NetError::AlreadyRunning));
    let echo = e.start_echo_server().unwrap();

    let id = e.dial(echo).unwrap();
    let r = block_on(e.wait_dial(id)).unwrap();
    assert_eq!(r.bytes, 1024);

    let pending = e.dial(UNROUTABLE.into()).unwrap();
    sleep(Duration::from_millis(200));
    assert_eq!(
        e.dial_state(pending),
        DialState::Pending,
        "unroutable dial must still be pending"
    );
    let t0 = Instant::now();
    assert!(e.cancel(pending));
    assert_eq!(
        block_on(e.wait_dial(pending)).unwrap_err(),
        NetError::Cancelled
    );
    assert!(
        t0.elapsed() < Duration::from_millis(250),
        "cancel took {:?}",
        t0.elapsed()
    );
    assert!(settle(|| e.status().live_dials == 0));

    // Bounded batches: capacity 16, so most of 40 test events are dropped and counted.
    let mut seen = 0;
    loop {
        let b = block_on(e.next_events(8, 50)).unwrap();
        assert!(b.events.len() <= 8);
        if b.events.is_empty() {
            assert!(b.dropped_total > 0 || seen > 0);
            break;
        }
        seen += b.events.len();
    }
    e.emit_test_events(40).unwrap();
    let b = block_on(e.next_events(64, 50)).unwrap();
    assert_eq!(b.events.len(), 16);
    assert!(b.dropped_total >= 24);

    // Stop with a dial pending: the wait resolves Stopped.
    let pending = e.dial(UNROUTABLE.into()).unwrap();
    let e2 = e.clone();
    let waiter = std::thread::spawn(move || block_on(e2.wait_dial(pending)));
    sleep(Duration::from_millis(100));
    assert!(e.stop());
    assert_eq!(waiter.join().unwrap().unwrap_err(), NetError::Stopped);
    assert!(!e.is_running());
    assert_eq!(e.dial("127.0.0.1:1".into()), Err(NetError::NotRunning));
    assert!(
        settle(|| open_socket_fds() == sockets0),
        "sockets {} vs {}",
        open_socket_fds(),
        sockets0
    );
    assert_eq!(e.status().open_sockets, 0);
}

#[test]
fn dropping_the_wait_cancels_the_dial() {
    let e = engine(None);
    e.start().unwrap();
    let id = e.dial(UNROUTABLE.into()).unwrap();
    {
        // Poll once, then drop: what a cancelled Swift task or Kotlin job does.
        let mut fut = Box::pin(e.wait_dial(id));
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(fut.as_mut().poll(&mut cx).is_pending());
    }
    assert!(settle(|| e.status().live_dials == 0));
    assert_eq!(e.dial_state(id), DialState::Unknown);
    e.stop();
}

#[test]
fn broken_cancel_must_fail() {
    let e = engine(Some("cancel"));
    e.start().unwrap();
    let id = e.dial(UNROUTABLE.into()).unwrap();
    sleep(Duration::from_millis(100));
    e.cancel(id);
    sleep(Duration::from_millis(300));
    assert_eq!(
        e.dial_state(id),
        DialState::Pending,
        "the control must leave the dial running"
    );
    e.stop();
}

#[test]
fn byte_path_probes() {
    for (mode, wrong_token_refused) in [(None, true), (Some("token"), false)] {
        let e = engine(mode);
        e.start().unwrap();
        e.start_byte_path(BytePathConfig {
            allowed_origin: "https://localhost".into(),
        })
        .unwrap();
        let probes = block_on(e.probe_byte_path()).unwrap();
        for p in &probes {
            if p.case_name == "wrong-token" || p.case_name == "missing-token" {
                assert_eq!(p.ok, wrong_token_refused, "{p:?}");
            } else {
                assert!(p.ok, "{p:?}");
            }
        }
        let report = Report::new("phase0.phone-byte-path".into());
        // No page in this test: the report must not pass.
        block_on(e.finish_byte_path(report.clone(), 100)).unwrap();
        assert_eq!(report.outcome(), "FAIL");
        e.stop();
    }
}

#[test]
fn report_shape() {
    let r = Report::new("phase0.phone-lifecycle".into());
    assert_eq!(r.outcome(), "INCOMPLETE");
    r.step("a".into(), true, Some(1.0), String::new());
    assert_eq!(r.outcome(), "PASS");
    let v: serde_json::Value = serde_json::from_str(&r.finish("host".into())).unwrap();
    assert_eq!(v["check"], "phase0.phone-lifecycle");
    assert_eq!(v["target"], "host");
    assert_eq!(v["outcome"], "PASS");
    assert!(v["build"].as_str().unwrap().contains('+'));
    r.step("a".into(), false, None, "x".into());
    assert_eq!(r.outcome(), "FAIL");
}
