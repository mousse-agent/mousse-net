//! E-R4: manifests, stale-manifest dialling and manual key rotation
//! through the app channel, against a real `mousse-relay` on loopback (Phase 3
//! §B.4 and §B.11). The check cell `phase3.relay-rotation` runs this file.
//! The cases live in `common/relay_rotation.rs`; `app_relay_remote.rs` runs
//! the same ones against a relay on another machine.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;
#[path = "common/relay_rotation.rs"]
mod rotation;

#[test]
fn a_manual_rotation_asks_nothing_and_an_offline_caller_comes_back_through_the_old_route() {
    rotation::a_manual_rotation_asks_nothing_and_an_offline_caller_comes_back_through_the_old_route(
    );
}

#[test]
fn a_stale_manifest_s_routes_are_still_dialled() {
    rotation::a_stale_manifest_s_routes_are_still_dialled();
}

#[test]
fn the_old_key_leaves_after_the_overlap() {
    rotation::the_old_key_leaves_after_the_overlap();
}
