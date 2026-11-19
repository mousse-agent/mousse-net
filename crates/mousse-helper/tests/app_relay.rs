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
