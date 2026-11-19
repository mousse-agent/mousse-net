//! E-R0 measurements against a running `mousse-relay` (docs/phase34-design.md
//! Part F, E-R0): dial cost, call setup with its accept leg, round trip
//! through a splice, splice throughput, and many open circuits held for a
//! memory sample.
//!
//!     relay_bench <enrollment link> [--mode all|setup|rtt|throughput|hold]
//!                 [--circuits N] [--mb N] [--hold N] [--hold-secs N]
//!
//! It enrolls a fresh target key with the link's code, so each run needs a
//! new link (`mousse-relay enroll`). Results go to stdout as `key value`
//! lines.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::pairing::RouteHost;
use mousse_net_core::relay::{Class, EnrollmentLink, RelayClientKey, RelayId, RelayMessage};
use mousse_relay::client::{Received, RelayConn};
use mousse_relay::os_rng;

struct Bench {
    addr: SocketAddr,
    host: String,
    relay: RelayId,
    target: RelayClientKey,
    callers: Vec<RelayClientKey>,
    handle: [u8; 32],
}

fn key() -> RelayClientKey {
    RelayClientKey::new(SoftwareKey::generate(&mut os_rng()))
}

async fn relay_msg(c: &mut RelayConn) -> RelayMessage {
    loop {
        match tokio::time::timeout(Duration::from_secs(30), c.recv()).await {
            Ok(Received::Relay(RelayMessage::Ping { .. })) => continue,
            Ok(Received::Relay(m)) => return m,
            Ok(other) => panic!("expected a relay message, got {other:?}"),
            Err(_) => panic!("timed out waiting for the relay"),
        }
    }
}

async fn peer(c: &mut RelayConn) -> Vec<u8> {
    match tokio::time::timeout(Duration::from_secs(60), c.recv()).await {
        Ok(Received::Peer(b)) => b,
        Ok(other) => panic!("expected peer bytes, got {other:?}"),
        Err(_) => panic!("timed out waiting for peer bytes"),
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn percentile(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i]
}

impl Bench {
    async fn dial(&self) -> RelayConn {
        RelayConn::dial(self.addr, &self.host, self.relay)
            .await
            .unwrap_or_else(|e| panic!("dial failed: {e:?}"))
    }

    async fn register(&self, code: Option<[u8; 16]>) -> RelayConn {
        let mut c = self.dial().await;
        let proof = self.target.register_proof(&self.relay, &c.binding);
        let msg = match code {
            Some(code) => RelayMessage::Enroll {
                key: self.target.public_key(),
                proof,
                code,
            },
            None => RelayMessage::Register {
                key: self.target.public_key(),
                proof,
                hosted: None,
            },
        };
        c.send(&msg).await.unwrap();
        match relay_msg(&mut c).await {
            RelayMessage::Registered { .. } => {}
            other => panic!("registration refused: {other:?}"),
        }
        c.send(&RelayMessage::AllowSet {
            sequence: 1,
            callers: self.callers.iter().map(|k| k.fingerprint()).collect(),
            invitations: vec![],
        })
        .await
        .unwrap();
        assert!(matches!(
            relay_msg(&mut c).await,
            RelayMessage::AllowSetOk { .. }
        ));
        c
    }

    /// One spliced circuit; returns (caller leg, accept leg, setup time,
    /// time the target spent dialing its accept leg).
    async fn connect(
        &self,
        reg: &mut RelayConn,
        caller: usize,
        class: Class,
    ) -> (RelayConn, RelayConn, Duration, Duration) {
        let c = &self.callers[caller];
        let mut leg = self.dial().await;
        let start = Instant::now();
        leg.send(&RelayMessage::Call {
            handle: self.handle,
            key: c.public_key(),
            proof: c.call_proof(&self.relay, &self.handle, &leg.binding, class),
            class,
        })
        .await
        .unwrap();
        let circuit = match relay_msg(reg).await {
            RelayMessage::Incoming { circuit, .. } => circuit,
            other => panic!("expected INCOMING, got {other:?}"),
        };
        let accept_start = Instant::now();
        let mut acc = self.dial().await;
        let accept_dial = accept_start.elapsed();
        acc.send(&RelayMessage::Accept {
            handle: self.handle,
            circuit,
            proof: self
                .target
                .accept_proof(&self.relay, &circuit, &acc.binding),
        })
        .await
        .unwrap();
        assert_eq!(relay_msg(&mut leg).await, RelayMessage::Spliced);
        let setup = start.elapsed();
        assert_eq!(relay_msg(&mut acc).await, RelayMessage::Spliced);
        (leg, acc, setup, accept_dial)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let link = EnrollmentLink::parse(args.first().expect("an enrollment link")).expect("link");
    let opt = |name: &str, default: u64| -> u64 {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map_or(default, |v| v.parse().expect("a number"))
    };
    let mode = args
        .iter()
        .position(|a| a == "--mode")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "all".into());
    let host = match &link.host {
        RouteHost::Ipv4(ip) => ip.to_string(),
        RouteHost::Ipv6(ip) => format!("[{ip}]"),
        RouteHost::Dns(n) => n.clone(),
    };
    let addr = (link.authority().as_str())
        .to_socket_addrs()
        .expect("address")
        .next()
        .expect("address");
    let target = key();
    let callers: Vec<RelayClientKey> = (0..64).map(|_| key()).collect();
    let bench = Bench {
        addr,
        host,
        relay: link.relay,
        handle: target.handle(&link.relay),
        target,
        callers,
    };
    let mut reg = bench.register(Some(link.code)).await;
    println!("enrolled 1");
    let all = mode == "all";

    if all || mode == "setup" {
        let mut dials = Vec::new();
        for _ in 0..30 {
            let t = Instant::now();
            let c = bench.dial().await;
            dials.push(ms(t.elapsed()));
            c.close().await;
        }
        let mut setups = Vec::new();
        let mut accepts = Vec::new();
        for i in 0..30 {
            let (leg, acc, setup, accept) =
                bench.connect(&mut reg, i % 8, Class::Interactive).await;
            setups.push(ms(setup));
            accepts.push(ms(accept));
            leg.close().await;
            acc.close().await;
        }
        println!("dial_ms_p50 {:.1}", percentile(&mut dials, 0.5));
        println!("dial_ms_p90 {:.1}", percentile(&mut dials, 0.9));
        println!("call_setup_ms_p50 {:.1}", percentile(&mut setups, 0.5));
        println!("call_setup_ms_p90 {:.1}", percentile(&mut setups, 0.9));
        println!(
            "accept_leg_dial_ms_p50 {:.1}",
            percentile(&mut accepts, 0.5)
        );
        println!(
            "accept_leg_dial_ms_p90 {:.1}",
            percentile(&mut accepts, 0.9)
        );
    }

    if all || mode == "rtt" {
        let (mut leg, mut acc, _, _) = bench.connect(&mut reg, 0, Class::Interactive).await;
        let echo = tokio::spawn(async move {
            while let Received::Peer(b) = acc.recv().await {
                if acc.send_raw(b).await.is_err() {
                    break;
                }
            }
        });
        let mut rtts = Vec::new();
        for i in 0..500u32 {
            let t = Instant::now();
            leg.send_raw(i.to_be_bytes().repeat(16)).await.unwrap();
            let back = peer(&mut leg).await;
            assert_eq!(back.len(), 64);
            rtts.push(ms(t.elapsed()));
        }
        println!("rtt_64b_ms_p50 {:.2}", percentile(&mut rtts, 0.5));
        println!("rtt_64b_ms_p99 {:.2}", percentile(&mut rtts, 0.99));
        leg.close().await;
        let _ = echo.await;
    }

    if all || mode == "throughput" {
        let mb = opt("--mb", 64);
        for n in [1usize, 4, 8] {
            if mode == "throughput"
                && opt("--circuits", 0) != 0
                && opt("--circuits", 0) as usize != n
            {
                continue;
            }
            let mut pairs = Vec::new();
            for i in 0..n {
                pairs.push(bench.connect(&mut reg, i, Class::Bulk).await);
            }
            let per = (mb as usize * 1_000_000) / n;
            let start = Instant::now();
            let mut tasks = Vec::new();
            for (mut leg, mut acc, _, _) in pairs {
                tasks.push(tokio::spawn(async move {
                    let send = async {
                        let mut left = per;
                        while left > 0 {
                            let len = left.min(60_000);
                            leg.send_raw(vec![0xa5; len]).await.unwrap();
                            left -= len;
                        }
                        leg
                    };
                    let recv = async {
                        let mut got = 0;
                        while got < per {
                            got += peer(&mut acc).await.len();
                        }
                        acc
                    };
                    let (leg, acc) = tokio::join!(send, recv);
                    leg.close().await;
                    acc.close().await;
                }));
            }
            for t in tasks {
                t.await.unwrap();
            }
            let secs = start.elapsed().as_secs_f64();
            println!(
                "throughput_mbyte_s_circuits_{n} {:.1}",
                (per * n) as f64 / 1e6 / secs
            );
        }
    }

    if mode == "hold" {
        let n = opt("--hold", 200) as usize;
        let mut held = Vec::new();
        for i in 0..n {
            let (leg, acc, _, _) = bench.connect(&mut reg, i % 64, Class::Interactive).await;
            held.push((leg, acc));
        }
        println!("holding_circuits {n}");
        println!("holding_connections {}", 2 * n + 1);
        tokio::time::sleep(Duration::from_secs(opt("--hold-secs", 20))).await;
        for (leg, acc) in held {
            leg.close().await;
            acc.close().await;
        }
    }
    reg.close().await;
}
