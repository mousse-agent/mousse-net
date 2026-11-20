//! E-R3: the helper as a relay target and a relay caller, through the app
//! channel, against a real `mousse-relay` on loopback (Phase 3 §B.4 to
//! §B.12). The check cell `phase3.relay-routes` runs this file. The cases
//! live in `common/relay_routes.rs`; `app_relay_remote.rs` runs the same
//! ones against a relay on another machine.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;
#[path = "common/relay_routes.rs"]
mod routes;

#[test]
fn app_cases_run_over_a_relay_route_with_bulk_on_its_own_connection_and_removal_closes_only_that_caller(
) {
    routes::app_cases_run_over_a_relay_route_with_bulk_on_its_own_connection_and_removal_closes_only_that_caller();
}

#[test]
fn caller_keys_are_per_pairing() {
    routes::caller_keys_are_per_pairing();
}

#[test]
fn a_relay_route_is_dialled_only_once_its_destination_is_approved() {
    routes::a_relay_route_is_dialled_only_once_its_destination_is_approved();
}

#[test]
fn relay_only_pairing_recovers_with_one_grant_and_only_for_that_grant() {
    routes::relay_only_pairing_recovers_with_one_grant_and_only_for_that_grant();
}

#[test]
fn a_grant_rides_a_recovery_circuit_only_for_its_own_invitation() {
    routes::a_grant_rides_a_recovery_circuit_only_for_its_own_invitation();
}

#[test]
fn removals_reach_the_relay_after_a_restart_too() {
    routes::removals_reach_the_relay_after_a_restart_too();
}

#[test]
fn removing_a_relay_ends_the_sessions_through_it() {
    routes::removing_a_relay_ends_the_sessions_through_it();
}

/// The secrets a caller is given for a host's relays (its pair secret, a
/// ticket's invitation tag) are never in a plain file: the host's pair
/// secret, derived on the host, appears nowhere in the caller's state.
#[test]
fn the_pair_secret_is_not_in_a_plain_file() {
    use common::*;
    use mousse_net_core::relay_endpoint::{derive_secret, PAIR_SECRET_INFO};
    use mousse_net_io::keystore::{relay_seed, KeyStorage};
    use mousse_net_io::store::{hex, unhex};
    use serde_json::{json, Value};

    let relay = relay_fixture::TestRelay::start();
    let a_end = Endpoint::init("rsa");
    let b_end = Endpoint::init("rsb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let reply = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(reply["relay"]["state"], "registered", "{reply}");
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    pair_apps(&mut a, &mut b);
    b.event("peer.keys", |m| m["identity"] == a.identity.as_str());
    // The secret A answered with, from A's seed and the salt A keeps.
    let grants: Value =
        serde_json::from_slice(&std::fs::read(a_end.dir.join("relay-grants.json")).unwrap())
            .unwrap();
    let salt = grants["keys"][0]["salt"].as_str().unwrap();
    let seed = relay_seed(&a_end.dir, "", KeyStorage::InsecureFile).unwrap();
    let secret = derive_secret(&seed, PAIR_SECRET_INFO, &unhex(salt).unwrap());
    let text = hex(secret.as_slice());
    // B has it (Phase 4's mailbox reads it), and no file of B's shows it.
    let peers = std::fs::read_to_string(b_end.dir.join("relay-peers.json")).unwrap();
    assert!(peers.contains("pair_secret"), "{peers}");
    for entry in std::fs::read_dir(&b_end.dir).unwrap() {
        let path = entry.unwrap().path();
        if let Ok(bytes) = std::fs::read(&path) {
            let shown = String::from_utf8_lossy(&bytes).to_lowercase();
            assert!(
                !shown.contains(&text),
                "{} holds the pair secret",
                path.display()
            );
        }
    }
}
