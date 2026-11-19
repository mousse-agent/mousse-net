//! E-L2: Plus sign-in through the app channel, against the test stand-in.
//! The code is typed in the browser (here: the stand-in approves it); the
//! helper polls until Plus answers, also after a lost answer, and keeps the
//! account and usage on disk so they show at once after a restart, even
//! while Plus is unreachable.

mod common;

use std::time::Duration;

use common::plus_standin::PlusStandIn;
use common::*;
use serde_json::json;

fn plus_app(end: &Endpoint, url: &str) -> App {
    let mut app = end.app("plus", &[("PLUS_URL", url), ("PLUS_RETRY_FIRST_MS", "100")]);
    app.hello();
    app
}

#[test]
fn plus_sign_in_with_a_typed_code_survives_a_lost_poll_answer() {
    let standin = PlusStandIn::start();
    let end = Endpoint::init("pluslink");
    let mut app = plus_app(&end, &standin.url());
    let status = app.call("plus.status", json!({}));
    assert_eq!(status["configured"], true);
    assert_eq!(status["linked"], false);

    let link = app.call("plus.link.start", json!({}));
    let code = link["user_code"].as_str().unwrap().to_owned();
    assert!(!code.is_empty());
    assert!(link["verify_url"].as_str().unwrap().starts_with("http"));
    // The browser step: the user types the code, Plus approves. The poll's
    // answer is lost once; the helper polls again and still learns it.
    standin.lose_next_answer("/v1/link/poll");
    std::thread::sleep(Duration::from_millis(200));
    assert!(standin.approve(&code).is_some());
    let done = app.event("plus.link", |m| m["state"] == "approved");
    assert_eq!(done["state"], "approved");
    let status = app.event("plus.status", |m| m["linked"] == true);
    assert_eq!(status["account"]["plan"], "active");
    assert!(status["usage"]["bulk"]["available"].as_u64().unwrap() > 0);

    // Another Plus origin: nothing of this one applies.
    drop(app);
    let other = PlusStandIn::start();
    let mut app = plus_app(&end, &other.url());
    assert_eq!(app.call("plus.status", json!({}))["linked"], false);
}

#[test]
fn plus_status_is_shown_from_disk_while_plus_is_down() {
    let standin = PlusStandIn::start();
    let url = standin.url();
    let end = Endpoint::init("plusoffline");
    let mut app = plus_app(&end, &url);
    let link = app.call("plus.link.start", json!({}));
    standin
        .approve(link["user_code"].as_str().unwrap())
        .unwrap();
    app.event("plus.status", |m| m["linked"] == true);
    drop(app);
    drop(standin);
    // Same origin, nothing listening: the stored account answers at once.
    let mut app = plus_app(&end, &url);
    let started = std::time::Instant::now();
    let status = app.call("plus.status", json!({}));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(status["linked"], true);
    assert_eq!(status["account"]["plan"], "active");
    let reply = app.request("plus.refresh", json!({}));
    assert_eq!(reply["error"], "unreachable");
    let reach = app.event("plus.reach", |m| m["reachable"] == false);
    assert!(reach["since"].as_u64().is_some());
}

#[test]
fn plus_link_denied_or_unknown_ends_the_poll() {
    let standin = PlusStandIn::start();
    let end = Endpoint::init("plusdeny");
    let mut app = plus_app(&end, &standin.url());
    let link = app.call("plus.link.start", json!({}));
    standin.deny(link["user_code"].as_str().unwrap());
    app.event("plus.link", |m| m["state"] == "denied");
    assert_eq!(app.call("plus.status", json!({}))["linked"], false);
    // A link Plus no longer knows (lost in a restore): start again.
    app.call("plus.link.start", json!({}));
    standin.fail_next("/v1/link/poll", "not_found", 404, None);
    app.event("plus.link", |m| m["state"] == "gone");
}

#[test]
fn plus_ops_without_a_plus_url_say_so() {
    let end = Endpoint::init("plusoff");
    let mut app = end.app("plusoff", &[]);
    app.hello();
    assert_eq!(app.call("plus.status", json!({}))["configured"], false);
    assert_eq!(
        app.request("plus.link.start", json!({}))["error"],
        "plus_off"
    );
}
