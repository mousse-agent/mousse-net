//! Drill scenarios. Each seed picks a variant, the devices, their clocks and
//! certificate lifetimes, the people's behaviour and the faults.

use mousse_net_core::pairing::{InvitationKind, Route as RouteHint, Ticket};

use crate::caller::Typist;
use crate::host::OwnerChoice;
use crate::sim::{DevId, Route, Sim};
use crate::world::{Script, World};
use crate::{Drill, RunConfig, RunOutcome};

pub(crate) const PAIRING_VARIANTS: &[&str] = &[
    "wrong-codes",
    "aborts",
    "reconnects",
    "race",
    "ticket-expiry",
    "host-restart",
    "fake-host",
    "in-person",
];

pub(crate) const HANDSHAKE_VARIANTS: &[&str] = &[
    "windows",
    "wrong-pin",
    "expiry-mid-channel",
    "renewal",
    "path-switch",
    "removal",
    "restart",
];

/// Every handshake variant: the picked ones, and `lan-flap`, which half the
/// `path-switch` seeds run.
pub(crate) const HANDSHAKE_ALL: &[&str] = &[
    "windows",
    "wrong-pin",
    "expiry-mid-channel",
    "renewal",
    "path-switch",
    "lan-flap",
    "removal",
    "restart",
];

pub(crate) const SHARED_VARIANTS: &[&str] = &[
    "deny-on-one",
    "remove-on-one",
    "wrong-endpoint",
    "machine-restart",
];

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub(crate) fn run(config: &RunConfig) -> RunOutcome {
    let mut world = World::new(Sim::new(*config));
    let variant = match config.drill {
        Drill::PairingLimits => pairing_limits(&mut world),
        Drill::Handshake => handshake(&mut world),
        Drill::SharedEndpoints => shared_endpoints(&mut world),
        Drill::RelayAdmission => crate::relay::run(&mut world.sim),
    };
    world.run();
    let World { sim, .. } = world;
    let violation = sim.check.violation.clone();
    let (events, end_ms) = (sim.events, sim.now);
    let (log_hash, log_lines, log) = sim.log.finish();
    RunOutcome {
        config: *config,
        variant,
        log_hash,
        log_lines,
        log,
        violation,
        events,
        end_ms,
    }
}

fn route(world: &mut World, name: &'static str, target: DevId, latency: (u64, u64)) -> usize {
    let latency_ms = world.sim.range(latency.0, latency.1);
    world.sim.routes.push(Route {
        name,
        target,
        hijack: None,
        partitioned: false,
        latency_ms,
    });
    world.sim.routes.len() - 1
}

fn header(world: &mut World, variant: &str) {
    let cfg = world.sim.cfg;
    world.sim.note(
        "sim",
        format_args!(
            "drill {} seed {} variant {variant}{}",
            cfg.drill.name(),
            cfg.seed,
            cfg.bug
                .map(|b| format!(" bug {}", b.name()))
                .unwrap_or_default()
        ),
    );
}

/// A route goes silent for a while, then heals.
fn maybe_partition(world: &mut World, permille: u32, routes: &[usize], window: (u64, u64)) {
    if world.sim.chance(permille) {
        let r = world.sim.pick(routes);
        let at = world.sim.range(window.0, window.1);
        let len = world.sim.range(2 * SEC, 10 * MIN);
        world.at(at, Script::Partition { route: r, on: true });
        world.at(
            at + len,
            Script::Partition {
                route: r,
                on: false,
            },
        );
    }
}

// ---- pairing-limits ---------------------------------------------------------------

const LAN: &str = "tcp://192.168.1.20:7443";
const TAILNET: &str = "tcp://100.101.102.103:7443";
const FAKE: &str = "tcp://203.0.113.9:7443";
/// A hint the joiner must skip (reserved scheme).
const RESERVED: &str = "wss://tunnel.example.net/join";

/// The routes a joiner dials: the ticket's hints, read with core's route
/// parser, mapped to simulated routes. Hints core skips are not dialled.
fn ticket_routes(world: &mut World, ticket: &Ticket) -> Vec<usize> {
    let mut out = Vec::new();
    for hint in &ticket.routes {
        match RouteHint::parse(hint) {
            Ok(_) => {
                if let Some(i) = world.sim.routes.iter().position(|r| r.name == hint) {
                    out.push(i);
                }
            }
            Err(skip) => world.sim.note(
                "sim",
                format_args!("joiner skips route hint {hint}: {skip:?}"),
            ),
        }
    }
    out
}

fn pairing_limits(world: &mut World) -> &'static str {
    let variant = world.sim.pick(PAIRING_VARIANTS);
    header(world, variant);
    let s = &mut world.sim;
    let small = [-300i64, -45, 0, 0, 0, 0, 30, 300];
    let skew_phone = if s.chance(80) {
        s.pick(&[-700i64, 700])
    } else {
        s.pick(&small)
    };
    let skew_laptop = s.pick(&small);

    let host = world.add_host("host", 0, 86_400);
    let phone = world.add_caller("phone", "phone", skew_phone, 86_400);
    let laptop =
        (variant == "race").then(|| world.add_caller("laptop", "laptop", skew_laptop, 86_400));
    let fake = (variant == "fake-host").then(|| world.add_host("fake", 0, 86_400));

    let lan = route(world, LAN, host, (1, 8));
    let tailnet = route(world, TAILNET, host, (20, 150));
    if let Some(f) = fake {
        route(world, FAKE, f, (20, 80));
    }

    let s = &mut world.sim;
    s.drop_permille = s.pick(&[0, 0, 100, 300]);
    s.drop_max = 1_500;

    let kind = match variant {
        "in-person" => InvitationKind::InPerson,
        "race" | "host-restart" => {
            if s.chance(500) {
                InvitationKind::InPerson
            } else {
                InvitationKind::SendLink
            }
        }
        _ => InvitationKind::SendLink,
    };
    let owner_choices = match variant {
        "in-person" => s.pick(&[
            &[OwnerChoice::Approve][..],
            &[
                OwnerChoice::Approve,
                OwnerChoice::Approve,
                OwnerChoice::Decline,
            ],
            &[OwnerChoice::Decline],
            &[OwnerChoice::Cancel],
        ]),
        _ => &[OwnerChoice::Approve][..],
    };
    let (h, sim) = world.hs(host);
    h.owner_choices = owner_choices.to_vec();
    let mut hints = vec![LAN.to_owned(), TAILNET.to_owned()];
    if sim.chance(200) {
        hints.insert(0, RESERVED.to_owned());
    }
    let created = h.create_invitation(sim, kind, hints);
    let (ticket, ticket_host) = match fake {
        Some(f) => {
            let (fh, sim) = world.hs(f);
            fh.malicious = true;
            let c = fh.create_invitation(sim, InvitationKind::SendLink, vec![FAKE.to_owned()]);
            (c.ticket, f)
        }
        _ => (created.ticket, host),
    };
    let routes = ticket_routes(world, &ticket);

    let mut joiners = vec![phone];
    joiners.extend(laptop);
    for (n, &j) in joiners.iter().enumerate() {
        let s = &mut world.sim;
        let typist = Typist {
            wrong_first: match variant {
                "wrong-codes" => s.pick(&[0, 1, 2, 3, 4]),
                "reconnects" => s.pick(&[1, 2, 3]),
                "fake-host" => u8::MAX,
                _ => s.pick(&[0, 0, 1, 2]),
            },
            delay: if variant == "ticket-expiry" && s.chance(500) {
                (5 * MIN, 15 * MIN)
            } else {
                (2 * SEC, 25 * SEC)
            },
            resend_permille: match variant {
                "aborts" => 300,
                _ => s.pick(&[0, 0, 100]),
            },
            abort_permille: match variant {
                "aborts" => 250,
                _ => s.pick(&[0, 0, 30]),
            },
            switch_permille: match variant {
                "reconnects" => 600,
                _ => s.pick(&[0, 100]),
            },
        };
        let dup = match variant {
            "reconnects" => 700,
            _ => s.pick(&[0, 200]),
        };
        let start = if variant == "ticket-expiry" && s.chance(500) {
            s.range(5 * MIN, 25 * MIN)
        } else {
            s.range(SEC, 20 * SEC)
        };
        let (c, _) = world.cs(j);
        c.ticket = Some(ticket.clone());
        c.expected_host = Some(ticket.host_identity);
        c.host_dev = ticket_host;
        c.routes = routes.clone();
        c.route_pref = n;
        c.typist = typist;
        c.dup_permille = dup;
        world.at(start, Script::JoinerStarts { dev: j });
    }

    match variant {
        "aborts" => {
            if world.sim.chance(200) {
                let at = world.sim.range(20 * SEC, 5 * MIN);
                world.at(at, Script::HostCancels { host });
            }
            if world.sim.chance(300) {
                let at = world.sim.range(10 * SEC, 3 * MIN);
                let down = world.sim.range(SEC, 10 * SEC);
                world.at(
                    at,
                    Script::Crash {
                        dev: phone,
                        keep: true,
                        down_ms: down,
                    },
                );
            }
        }
        "host-restart" => {
            let crashes = world.sim.range(1, 2);
            for _ in 0..crashes {
                let at = world.sim.range(3 * SEC, 40 * SEC);
                let keep = world.sim.chance(500);
                let down = world.sim.range(2 * SEC, 20 * SEC);
                world.at(
                    at,
                    Script::Crash {
                        dev: host,
                        keep,
                        down_ms: down,
                    },
                );
            }
        }
        _ => {}
    }
    maybe_partition(world, 300, &[lan, tailnet], (5 * SEC, 5 * MIN));
    world.end_ms = 45 * MIN;
    world.stop_when_settled = true;
    variant
}

// ---- handshake -----------------------------------------------------------------------

fn handshake(world: &mut World) -> &'static str {
    let mut variant = world.sim.pick(HANDSHAKE_VARIANTS);
    // Half the path-switch seeds flap the LAN instead (drawn here so the
    // other variants keep their seeds).
    if variant == "path-switch" && world.sim.chance(500) {
        variant = "lan-flap";
    }
    header(world, variant);
    let s = &mut world.sim;
    let wide = [
        -900i64, -650, -610, -590, -300, -30, 30, 300, 590, 610, 650, 900,
    ];
    let small = [0i64, 0, 0, -30, 30, -200, 200];
    let skew_host = if s.chance(150) { s.pick(&wide) } else { 0 };
    let skew_laptop = if variant == "windows" || s.chance(150) {
        s.pick(&wide)
    } else {
        s.pick(&small)
    };
    let (host_life, laptop_life) = match variant {
        "expiry-mid-channel" => (86_400, s.pick(&[2_400, 3_600])),
        "renewal" => (s.pick(&[2_400, 3_600]), s.pick(&[2_400, 3_600])),
        _ => (
            s.pick(&[2_400, 3_600, 7_200, 86_400]),
            s.pick(&[2_400, 3_600, 5_400]),
        ),
    };
    let host_lead = s.pick(&[1_800, 1_800, 1_800, 600, 0]);
    let laptop_lead = if variant == "expiry-mid-channel" {
        1_800
    } else {
        s.pick(&[1_800, 1_800, 600])
    };

    let host = world.add_host("host", skew_host, host_life);
    let laptop = world.add_caller("laptop", "laptop", skew_laptop, laptop_life);
    let rogue = world.add_host("rogue", 0, 86_400);
    let stranger = world.add_caller("stranger", "stranger", 0, 86_400);
    let lan = route(world, LAN, host, (1, 8));
    let tailnet = route(world, TAILNET, host, (20, 150));

    let s = &mut world.sim;
    s.drop_permille = match variant {
        "path-switch" | "lan-flap" => 200,
        _ => s.pick(&[0, 0, 50, 200]),
    };
    s.drop_max = 30_000;
    let grant_expiry = (variant == "removal" && s.chance(300)).then(|| s.range(10 * 60, 2 * 3_600));
    let eager = s.chance(300);

    world.sim.note(
        "sim",
        format_args!(
            "host skew {skew_host}s cert {host_life}s lead {host_lead}s, laptop skew {skew_laptop}s cert {laptop_life}s lead {laptop_lead}s"
        ),
    );
    let host_identity = world.sim.identities[host];
    let laptop_identity = world.sim.identities[laptop];
    let (h, sim) = world.hs(host);
    h.renew_lead = host_lead;
    h.add_grant(sim, laptop_identity, "laptop", grant_expiry);
    let (c, _) = world.cs(laptop);
    c.renew_lead = laptop_lead;
    c.expected_host = Some(host_identity);
    c.host_dev = host;
    c.routes = vec![lan, tailnet];
    c.keystroke_ms = (5 * SEC, 60 * SEC);
    c.eager_streams = eager;
    let (x, _) = world.cs(stranger);
    x.expected_host = Some(host_identity);
    x.host_dev = host;
    x.routes = vec![lan];
    world.at(SEC, Script::PairedStarts { dev: laptop });

    let end = 3 * 60 * MIN;
    match variant {
        "windows" => {
            let jumps = world.sim.range(1, 3);
            for _ in 0..jumps {
                let dev = world.sim.pick(&[host, laptop]);
                let secs = world
                    .sim
                    .pick(&[-1_300i64, -700, -610, -590, 590, 610, 700, 1_300]);
                let at = world.sim.range(MIN, end);
                world.at(at, Script::ClockJump { dev, secs });
            }
        }
        "wrong-pin" => {
            let r = world.sim.pick(&[lan, tailnet]);
            let from = world.sim.range(30 * SEC, 2 * 60 * MIN);
            let len = world.sim.range(MIN, 30 * MIN);
            world.at(
                from,
                Script::Hijack {
                    route: r,
                    by: Some(rogue),
                },
            );
            world.at(from + len, Script::Hijack { route: r, by: None });
            let switches = world.sim.range(1, 4);
            for _ in 0..switches {
                let at = world.sim.range(from, from + len);
                world.at(at, Script::PathSwitch { dev: laptop });
            }
        }
        "expiry-mid-channel" => {
            // New connections are refused from before renewal until after
            // the deadline (sometimes healing earlier), so the live channel
            // must close at its deadline.
            let renew_ms = (laptop_life - 1_800) * SEC;
            let from = world
                .sim
                .range(MIN, renew_ms.saturating_sub(2 * MIN).max(MIN + 1));
            let len = world.sim.range(20 * MIN, 2 * laptop_life * SEC);
            for r in [lan, tailnet] {
                world.at(from, Script::Refuse { route: r, on: true });
                world.at(
                    from + len,
                    Script::Refuse {
                        route: r,
                        on: false,
                    },
                );
            }
        }
        "path-switch" => {
            let mut at = world.sim.range(MIN, 15 * MIN);
            while at < end {
                world.at(at, Script::PathSwitch { dev: laptop });
                at += world.sim.range(MIN, 15 * MIN);
            }
        }
        "lan-flap" => {
            // The LAN comes and goes. While it is down the laptop moves to
            // the tailnet; soon after it heals the LAN probe moves the
            // laptop back, sometimes into a LAN that drops again within
            // seconds (a flap), while the move is still being confirmed.
            let mut at = world.sim.range(30 * SEC, 5 * MIN);
            while at < end {
                let down = world.sim.range(2 * SEC, 3 * MIN);
                world.at(
                    at,
                    Script::Partition {
                        route: lan,
                        on: true,
                    },
                );
                let away = at + world.sim.range(0, down);
                world.at(away, Script::PathSwitch { dev: laptop });
                let healed = at + down;
                world.at(
                    healed,
                    Script::Partition {
                        route: lan,
                        on: false,
                    },
                );
                let probe = healed + world.sim.range(SEC, 30 * SEC);
                world.at(probe, Script::PathSwitch { dev: laptop });
                at = if world.sim.chance(500) {
                    // Flap: down again while or just after the move.
                    probe + world.sim.range(0, 5 * SEC)
                } else {
                    probe + world.sim.range(MIN, 20 * MIN)
                };
            }
        }
        "removal" => {
            let at = world.sim.range(30 * SEC, 2 * 60 * MIN);
            let deny = world.sim.chance(300);
            world.at(
                at,
                Script::RemoveDevice {
                    host,
                    of: laptop,
                    deny,
                },
            );
            // Sometimes the host restarts with its store kept, and the owner
            // pairs the laptop again.
            if !deny && world.sim.chance(400) {
                let crash = at + world.sim.range(10 * SEC, 10 * MIN);
                let down = world.sim.range(2 * SEC, 30 * SEC);
                world.at(
                    crash,
                    Script::Crash {
                        dev: host,
                        keep: true,
                        down_ms: down,
                    },
                );
                let again = crash + down + world.sim.range(10 * SEC, 5 * MIN);
                world.at(again, Script::AddDevice { host, of: laptop });
            }
        }
        "restart" => {
            let crashes = world.sim.range(1, 2);
            for _ in 0..crashes {
                let at = world.sim.range(MIN, 2 * 60 * MIN);
                let keep = world.sim.chance(600);
                let down = world.sim.range(2 * SEC, MIN);
                world.at(
                    at,
                    Script::Crash {
                        dev: host,
                        keep,
                        down_ms: down,
                    },
                );
            }
            if world.sim.chance(300) {
                let at = world.sim.range(MIN, 2 * 60 * MIN);
                let down = world.sim.range(2 * SEC, MIN);
                world.at(
                    at,
                    Script::Crash {
                        dev: laptop,
                        keep: true,
                        down_ms: down,
                    },
                );
            }
        }
        _ => {}
    }
    if variant == "removal" || world.sim.chance(300) {
        let at = world.sim.range(10 * SEC, 60 * MIN);
        world.at(at, Script::IntruderStarts { dev: stranger });
    }
    maybe_partition(world, 250, &[lan, tailnet], (MIN, end));
    world.end_ms = end;
    variant
}

// ---- shared-endpoints ------------------------------------------------------------------

const DESK_A_LAN: &str = "tcp://192.168.1.30:7443";
const DESK_B_LAN: &str = "tcp://192.168.1.30:7444";
const DESK_A_TAILNET: &str = "tcp://100.64.0.30:7443";
const DESK_B_TAILNET: &str = "tcp://100.64.0.30:7444";

/// Two profiles on one computer: endpoints `desk-a` and `desk-b`, same
/// addresses, different ports and keys. Each has its own phone; one laptop
/// identity is granted on both. The laptop is modelled as two callers that
/// share one identity key, one per endpoint session.
fn shared_endpoints(world: &mut World) -> &'static str {
    let variant = world.sim.pick(SHARED_VARIANTS);
    header(world, variant);
    let skew_machine = world.sim.pick(&[0i64, 0, -45, 30]);
    let a = world.add_host("desk-a", skew_machine, 86_400);
    let b = world.add_host("desk-b", skew_machine, 86_400);
    let phone_a = world.add_caller("phone-a", "phone-a", 0, 86_400);
    let phone_b = world.add_caller("phone-b", "phone-b", 0, 86_400);
    let lap_a = world.add_caller("laptop>a", "laptop", 0, 86_400);
    let lap_b = world.add_caller("laptop>b", "laptop", 0, 86_400);
    world.machine = vec![a, b];

    let a_lan = route(world, DESK_A_LAN, a, (1, 8));
    let b_lan = route(world, DESK_B_LAN, b, (1, 8));
    let a_tail = route(world, DESK_A_TAILNET, a, (20, 120));
    let b_tail = route(world, DESK_B_TAILNET, b, (20, 120));
    world.sim.drop_permille = world.sim.pick(&[0, 0, 50, 150]);
    world.sim.drop_max = 30_000;

    let shared_table = world.sim.bug(crate::Bug::SharedGrantTable);
    let ids = |w: &World, d: DevId| w.sim.identities[d];
    let (pa, pb, lap) = (ids(world, phone_a), ids(world, phone_b), ids(world, lap_a));
    for (host, own, name) in [(a, pa, "phone-a"), (b, pb, "phone-b")] {
        let (h, sim) = world.hs(host);
        h.add_grant(sim, own, name, None);
        h.add_grant(sim, lap, "laptop", None);
    }
    if shared_table {
        // Planted bug: one grant table for the whole machine.
        let (h, sim) = world.hs(a);
        h.add_grant(sim, pb, "phone-b", None);
        let (h, sim) = world.hs(b);
        h.add_grant(sim, pa, "phone-a", None);
    }

    // Discovery on the shared machine finds both endpoints; a caller may try
    // the other profile's port first. A pin mismatch moves it to the next
    // candidate.
    for (dev, host, own, other) in [
        (phone_a, a, vec![a_lan, a_tail], b_lan),
        (phone_b, b, vec![b_lan, b_tail], a_lan),
        (lap_a, a, vec![a_lan, a_tail], b_lan),
        (lap_b, b, vec![b_lan, b_tail], a_lan),
    ] {
        let s = &mut world.sim;
        let mut routes = own;
        if s.chance(500) {
            routes.insert(0, other);
        } else {
            routes.push(other);
        }
        let start = s.range(SEC, 5 * SEC);
        let eager = s.chance(300);
        let pin = world.sim.identities[host];
        let (c, _) = world.cs(dev);
        c.expected_host = Some(pin);
        c.host_dev = host;
        c.routes = routes;
        c.keystroke_ms = (5 * SEC, 60 * SEC);
        c.eager_streams = eager;
        world.at(start, Script::PairedStarts { dev });
    }

    let end = 45 * MIN;
    let remove = |world: &mut World, deny: bool| {
        let host = world.sim.pick(&[a, b]);
        let of = if world.sim.chance(700) {
            if host == a {
                lap_a
            } else {
                lap_b
            }
        } else if host == a {
            phone_a
        } else {
            phone_b
        };
        let at = world.sim.range(MIN, end - 10 * MIN);
        world.at(at, Script::RemoveDevice { host, of, deny });
    };
    match variant {
        "deny-on-one" => remove(world, true),
        "remove-on-one" => remove(world, false),
        "wrong-endpoint" => {
            // The two profiles swap ports for a while (B restarted first and
            // took A's port).
            let from = world.sim.range(MIN, 25 * MIN);
            let len = world.sim.range(MIN, 15 * MIN);
            world.at(
                from,
                Script::Hijack {
                    route: a_lan,
                    by: Some(b),
                },
            );
            world.at(
                from,
                Script::Hijack {
                    route: b_lan,
                    by: Some(a),
                },
            );
            world.at(
                from + len,
                Script::Hijack {
                    route: a_lan,
                    by: None,
                },
            );
            world.at(
                from + len,
                Script::Hijack {
                    route: b_lan,
                    by: None,
                },
            );
            for dev in [phone_a, phone_b, lap_a, lap_b] {
                let at = world.sim.range(from, from + len);
                world.at(at, Script::PathSwitch { dev });
            }
        }
        "machine-restart" => {
            let at = world.sim.range(MIN, 30 * MIN);
            let down = world.sim.range(5 * SEC, MIN);
            for host in [a, b] {
                world.at(
                    at,
                    Script::Crash {
                        dev: host,
                        keep: true,
                        down_ms: down,
                    },
                );
            }
            let len = world.sim.range(MIN, 10 * MIN);
            world.at(
                at + down,
                Script::Hijack {
                    route: a_lan,
                    by: Some(b),
                },
            );
            world.at(
                at + down,
                Script::Hijack {
                    route: b_lan,
                    by: Some(a),
                },
            );
            world.at(
                at + down + len,
                Script::Hijack {
                    route: a_lan,
                    by: None,
                },
            );
            world.at(
                at + down + len,
                Script::Hijack {
                    route: b_lan,
                    by: None,
                },
            );
        }
        _ => {}
    }
    if world.sim.chance(500) {
        let deny = world.sim.chance(500);
        remove(world, deny);
    }
    maybe_partition(world, 200, &[a_tail, b_tail], (MIN, end));
    world.end_ms = end;
    variant
}
