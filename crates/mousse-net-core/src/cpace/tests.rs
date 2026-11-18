use core::convert::Infallible;

use curve25519_dalek::scalar::Scalar;
use rand_core::{TryCryptoRng, TryRng};
use serde_json::Value;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use super::primitives::{
    self, calculate_generator, generator_hash, generator_string, isk_input, lv_cat, scalar_mult,
    scalar_mult_vfy, IDENTITY,
};
use super::*;

const DRAFT: &str = include_str!("../../../../spec/vectors/cpace-ristretto255-sha512.json");
const MOUSSE: &str = include_str!("../../../../spec/vectors/cpace-ristretto255-sha512-mousse.json");

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("vector file is valid JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn arr32(v: &Value) -> [u8; 32] {
    hex(v).try_into().expect("32 bytes")
}

fn scalar(v: &Value) -> Zeroizing<Scalar> {
    Zeroizing::new(Option::from(Scalar::from_canonical_bytes(arr32(v))).expect("canonical scalar"))
}

/// A deterministic RNG for tests: SHA-512 of a seed and a counter.
struct TestRng {
    seed: u64,
    counter: u64,
}

impl TestRng {
    fn new(seed: u64) -> Self {
        TestRng { seed, counter: 0 }
    }
}

impl TryRng for TestRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(64) {
            let mut h = Sha512::new();
            h.update(self.seed.to_le_bytes());
            h.update(self.counter.to_le_bytes());
            self.counter += 1;
            let out = h.finalize();
            chunk.copy_from_slice(&out[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

// Draft helpers that Mousse does not use (symmetric setting, sid output),
// kept here only to check the draft's vectors bit for bit.
fn lexiographically_larger(a: &[u8], b: &[u8]) -> bool {
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return x > y;
        }
    }
    a.len() > b.len()
}

fn o_cat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (first, second) = if lexiographically_larger(a, b) { (a, b) } else { (b, a) };
    [b"oc".as_slice(), first, second].concat()
}

fn transcript_ir(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
    [lv_cat(&[ya, ada]), lv_cat(&[yb, adb])].concat()
}

fn transcript_oc(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
    o_cat(&lv_cat(&[ya, ada]), &lv_cat(&[yb, adb]))
}

const SID: &[u8] = b"0123456789abcdef-attempt-1";

fn inputs<'a>(prs: &'a [u8], ci: &'a [u8], ad: &'a [u8]) -> Inputs<'a> {
    Inputs { prs, ci, sid: SID, ad }
}

// ---- Draft Appendix A ----

#[test]
fn string_functions_match_draft_appendix_a() {
    let v = json(DRAFT);
    for case in v["prepend_len"].as_array().unwrap() {
        let mut out = Vec::new();
        primitives::push_prepend_len(&hex(&case["input"]), &mut out);
        assert_eq!(out, hex(&case["output"]));
    }
    for case in v["lv_cat"].as_array().unwrap() {
        let parts: Vec<Vec<u8>> = case["inputs"].as_array().unwrap().iter().map(hex).collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        assert_eq!(lv_cat(&refs), hex(&case["output"]));
    }
    for case in v["lexiographically_larger"].as_array().unwrap() {
        assert_eq!(
            lexiographically_larger(&hex(&case["a"]), &hex(&case["b"])),
            case["larger"].as_bool().unwrap()
        );
    }
    for case in v["o_cat"].as_array().unwrap() {
        assert_eq!(o_cat(&hex(&case["a"]), &hex(&case["b"])), hex(&case["output"]));
    }
    for (name, f) in [
        ("transcript_ir", transcript_ir as fn(&[u8], &[u8], &[u8], &[u8]) -> Vec<u8>),
        ("transcript_oc", transcript_oc),
    ] {
        for case in v[name].as_array().unwrap() {
            let got = f(&hex(&case["Ya"]), &hex(&case["ADa"]), &hex(&case["Yb"]), &hex(&case["ADb"]));
            assert_eq!(got, hex(&case["output"]), "{name}");
        }
    }
}

// ---- Draft Appendix B.3 ----

#[test]
fn generator_matches_draft_b3_1() {
    let d = &json(DRAFT)["cpace"];
    let (prs, ci, sid) = (hex(&d["PRS"]), hex(&d["CI"]), hex(&d["sid"]));
    assert_eq!(hex(&d["DSI"]), primitives::DSI);
    assert_eq!(d["s_in_bytes"].as_u64(), Some(primitives::S_IN_BYTES as u64));
    let gen_str = generator_string(&prs, &ci, &sid);
    assert_eq!(&gen_str[..], &hex(&d["generator_string"])[..]);
    // DSI (1+17) and PRS (1+8) are followed by the zero padding's length byte.
    assert_eq!(gen_str[18 + 9], d["zpad_len"].as_u64().unwrap() as u8);
    assert_eq!(&generator_hash(&prs, &ci, &sid)[..], &hex(&d["generator_hash"])[..]);
    let g = calculate_generator(&prs, &ci, &sid);
    assert_eq!(g.compress().to_bytes(), arr32(&d["g"]));
}

#[test]
fn shares_and_k_match_draft_b3_2_to_b3_4() {
    let d = &json(DRAFT)["cpace"];
    let (prs, ci, sid) = (hex(&d["PRS"]), hex(&d["CI"]), hex(&d["sid"]));
    let g = calculate_generator(&prs, &ci, &sid);
    let (ya, yb) = (scalar(&d["ya"]), scalar(&d["yb"]));
    let (ya_pt, yb_pt) = (arr32(&d["Ya"]), arr32(&d["Yb"]));
    assert_eq!(scalar_mult(&ya, &g), ya_pt);
    assert_eq!(scalar_mult(&yb, &g), yb_pt);
    assert_eq!(*scalar_mult_vfy(&ya, &yb_pt), arr32(&d["K"]));
    assert_eq!(*scalar_mult_vfy(&yb, &ya_pt), arr32(&d["K"]));

    // The same values through the public state machine.
    let ada = hex(&d["ADa"]);
    let a_in = Inputs { prs: &prs, ci: &ci, sid: &sid, ad: &ada };
    let (_, msg_a) = Initiator::start_with_scalar(&a_in, ya);
    assert_eq!(msg_a, lv_cat(&[&ya_pt, &ada]));
}

#[test]
fn isk_matches_draft_b3_5_to_b3_7() {
    let d = &json(DRAFT)["cpace"];
    let sid = hex(&d["sid"]);
    let k = arr32(&d["K"]);
    let (ya_pt, ada, yb_pt, adb) = (hex(&d["Ya"]), hex(&d["ADa"]), hex(&d["Yb"]), hex(&d["ADb"]));
    assert_eq!(hex(&d["DSI_ISK"]), primitives::DSI_ISK);

    let t_ir = transcript_ir(&ya_pt, &ada, &yb_pt, &adb);
    assert_eq!(t_ir, hex(&d["transcript_ir"]));
    assert_eq!(&isk_input(&sid, &k, &[&t_ir])[..], &hex(&d["isk_input_ir"])[..]);
    assert_eq!(&primitives::isk(&sid, &k, &[&t_ir])[..], &hex(&d["ISK_IR"])[..]);

    let t_oc = transcript_oc(&ya_pt, &ada, &yb_pt, &adb);
    assert_eq!(t_oc, hex(&d["transcript_oc"]));
    assert_eq!(&isk_input(&sid, &k, &[&t_oc])[..], &hex(&d["isk_input_oc"])[..]);
    assert_eq!(&primitives::isk(&sid, &k, &[&t_oc])[..], &hex(&d["ISK_SY"])[..]);

    let sid_out = |t: &[u8]| Sha512::digest([b"CPaceSidOutput".as_slice(), t].concat()).to_vec();
    assert_eq!(sid_out(&t_ir), hex(&d["sid_output_ir"]));
    assert_eq!(sid_out(&t_oc), hex(&d["sid_output_oc"]));
}

#[test]
fn full_run_with_draft_scalars_gives_draft_isk() {
    let d = &json(DRAFT)["cpace"];
    let (prs, ci, sid, ada, adb) = (hex(&d["PRS"]), hex(&d["CI"]), hex(&d["sid"]), hex(&d["ADa"]), hex(&d["ADb"]));
    let a_in = Inputs { prs: &prs, ci: &ci, sid: &sid, ad: &ada };
    let b_in = Inputs { prs: &prs, ci: &ci, sid: &sid, ad: &adb };
    let (a, msg_a) = Initiator::start_with_scalar(&a_in, scalar(&d["ya"]));
    let (b, msg_b) = Responder::respond_with_scalar(&b_in, &msg_a, scalar(&d["yb"])).unwrap();
    let (a_done, msg_c) = a.finish(&msg_b).unwrap();
    let b_done = b.finish(&msg_c).unwrap();
    assert_eq!(&a_done.isk().as_bytes()[..], &hex(&d["ISK_IR"])[..]);
    assert_eq!(&b_done.isk().as_bytes()[..], &hex(&d["ISK_IR"])[..]);
    assert_eq!(a_done.peer_ad(), &adb[..]);
    assert_eq!(b_done.peer_ad(), &ada[..]);
}

#[test]
fn scalar_mult_matches_draft_b3_10_and_b3_11() {
    let v = json(DRAFT);
    let ok = &v["scalar_mult_valid"];
    let s = scalar(&ok["s"]);
    let x = arr32(&ok["X"]);
    let decoded = curve25519_dalek::ristretto::CompressedRistretto(x).decompress().unwrap();
    assert_eq!(scalar_mult(&s, &decoded), arr32(&ok["scalar_mult"]));
    assert_eq!(*scalar_mult_vfy(&s, &x), arr32(&ok["scalar_mult_vfy"]));

    let bad = &v["scalar_mult_vfy_invalid"];
    let s = scalar(&bad["s"]);
    assert_eq!(arr32(&bad["result"]), IDENTITY);
    for p in bad["points"].as_array().unwrap() {
        let k = scalar_mult_vfy(&s, &arr32(p));
        assert_eq!(*k, IDENTITY);
        assert!(bool::from(primitives::is_identity(&k)));
    }
}

// ---- Mousse profile vectors (key confirmation, framing, rejections) ----

fn mousse_inputs(c: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (hex(&c["PRS"]), hex(&c["CI"]), hex(&c["sid"]))
}

#[test]
fn mousse_vectors_reproduce_bit_exact() {
    let v = json(MOUSSE);
    let c = &v["common"];
    let (prs, ci, sid) = mousse_inputs(c);
    for vec in v["vectors"].as_array().unwrap() {
        let (ada, adb) = (hex(&vec["ADa"]), hex(&vec["ADb"]));
        let a_in = Inputs { prs: &prs, ci: &ci, sid: &sid, ad: &ada };
        let b_in = Inputs { prs: &prs, ci: &ci, sid: &sid, ad: &adb };
        let (a, msg_a) = Initiator::start_with_scalar(&a_in, scalar(&c["ya"]));
        assert_eq!(msg_a, hex(&vec["msg_a"]));
        let (b, msg_b) = Responder::respond_with_scalar(&b_in, &msg_a, scalar(&c["yb"])).unwrap();
        assert_eq!(msg_b, hex(&vec["msg_b"]));
        let (a_done, msg_c) = a.finish(&msg_b).unwrap();
        assert_eq!(msg_c, hex(&vec["msg_c"]));
        let b_done = b.finish(&msg_c).unwrap();

        let isk = hex(&vec["ISK"]);
        assert_eq!(&a_done.isk().as_bytes()[..], &isk[..]);
        assert_eq!(&b_done.isk().as_bytes()[..], &isk[..]);
        let mac_key = primitives::mac_key(&sid, a_done.isk().as_bytes());
        assert_eq!(&mac_key[..], &hex(&vec["mac_key"])[..]);
        assert_eq!(&primitives::tag(&mac_key, &msg_a)[..], &hex(&vec["Ta"])[..]);
        assert_eq!(&msg_b[msg_b.len() - TAG_LEN..], &hex(&vec["Tb"])[..]);
    }
}

fn error_name(e: CpaceError) -> &'static str {
    match e {
        CpaceError::EmptyPassword => "EmptyPassword",
        CpaceError::SidTooShort => "SidTooShort",
        CpaceError::AdTooLong => "AdTooLong",
        CpaceError::Malformed => "Malformed",
        CpaceError::InvalidPoint => "InvalidPoint",
        CpaceError::ConfirmationFailed => "ConfirmationFailed",
    }
}

#[test]
fn mousse_rejection_vectors_fail_with_the_listed_error() {
    let v = json(MOUSSE);
    let c = &v["common"];
    let (prs, ci, sid) = mousse_inputs(c);
    let good = &v["vectors"][0];
    let (ada, adb) = (hex(&good["ADa"]), hex(&good["ADb"]));
    let a_in = Inputs { prs: &prs, ci: &ci, sid: &sid, ad: &ada };
    let b_in = Inputs { prs: &prs, ci: &ci, sid: &sid, ad: &adb };
    let rejections = v["rejections"].as_array().unwrap();
    assert!(rejections.len() >= 20);
    for r in rejections {
        let msg = hex(&r["message"]);
        let got = match r["stage"].as_str().unwrap() {
            "msg_a" => Responder::respond_with_scalar(&b_in, &msg, scalar(&c["yb"])).err(),
            "msg_b" => Initiator::start_with_scalar(&a_in, scalar(&c["ya"])).0.finish(&msg).err(),
            "msg_c" => {
                let (b, _) = Responder::respond_with_scalar(&b_in, &hex(&good["msg_a"]), scalar(&c["yb"])).unwrap();
                b.finish(&msg).err()
            }
            other => panic!("unknown stage {other}"),
        };
        assert_eq!(
            got.map(error_name),
            Some(r["error"].as_str().unwrap()),
            "rejection {} at {}",
            r["name"],
            r["stage"]
        );
    }
}

// ---- Behaviour with random scalars ----

/// Runs a full exchange. Returns both results, or the first error.
fn run(
    a_in: &Inputs<'_>,
    b_in: &Inputs<'_>,
    seed: u64,
) -> Result<(Confirmed, Confirmed), CpaceError> {
    let mut rng = TestRng::new(seed);
    let (a, msg_a) = Initiator::start(a_in, &mut rng)?;
    let (b, msg_b) = Responder::respond(b_in, &msg_a, &mut rng)?;
    let (a_done, msg_c) = a.finish(&msg_b)?;
    let b_done = b.finish(&msg_c)?;
    Ok((a_done, b_done))
}

#[test]
fn same_code_and_inputs_agree_on_isk() {
    let (a, b) = run(&inputs(b"493017", b"ci", b"joiner"), &inputs(b"493017", b"ci", b"host"), 1).unwrap();
    assert_eq!(a.isk().as_bytes(), b.isk().as_bytes());
    assert_eq!(a.peer_ad(), b"host");
    assert_eq!(b.peer_ad(), b"joiner");
}

#[test]
fn each_run_uses_fresh_scalars() {
    let i = inputs(b"493017", b"ci", b"");
    let mut rng = TestRng::new(7);
    let (_, m1) = Initiator::start(&i, &mut rng).unwrap();
    let (_, m2) = Initiator::start(&i, &mut rng).unwrap();
    assert_ne!(m1, m2);
    let (x, _) = run(&i, &i, 8).unwrap();
    let (y, _) = run(&i, &i, 9).unwrap();
    assert_ne!(x.isk().as_bytes(), y.isk().as_bytes());
}

#[test]
fn wrong_code_fails_confirmation() {
    let err = run(&inputs(b"493017", b"ci", b""), &inputs(b"493018", b"ci", b""), 2).unwrap_err();
    assert_eq!(err, CpaceError::ConfirmationFailed);
}

#[test]
fn different_channel_identifier_fails_confirmation() {
    let err = run(&inputs(b"493017", b"ticket-1", b""), &inputs(b"493017", b"ticket-2", b""), 3).unwrap_err();
    assert_eq!(err, CpaceError::ConfirmationFailed);
}

#[test]
fn different_session_id_fails_confirmation() {
    let a_in = inputs(b"493017", b"ci", b"");
    let b_in = Inputs { sid: b"0123456789abcdef-attempt-2", ..a_in };
    assert_eq!(run(&a_in, &b_in, 4).unwrap_err(), CpaceError::ConfirmationFailed);
}

/// The initiator's view of ADb differs from what the responder sent.
#[test]
fn responder_ad_changed_in_transit_fails_at_initiator() {
    let mut rng = TestRng::new(5);
    let (a, msg_a) = Initiator::start(&inputs(b"493017", b"ci", b"A"), &mut rng).unwrap();
    let (_, mut msg_b) = Responder::respond(&inputs(b"493017", b"ci", b"B"), &msg_a, &mut rng).unwrap();
    msg_b[34] ^= 0x01; // the AD byte after 0x20, Yb and the length byte
    assert_eq!(a.finish(&msg_b).unwrap_err(), CpaceError::ConfirmationFailed);
}

/// The responder's view of ADa differs from what the initiator sent.
#[test]
fn initiator_ad_changed_in_transit_fails() {
    let mut rng = TestRng::new(6);
    let (a, mut msg_a) = Initiator::start(&inputs(b"493017", b"ci", b"A"), &mut rng).unwrap();
    msg_a[34] ^= 0x01;
    let (_, msg_b) = Responder::respond(&inputs(b"493017", b"ci", b"B"), &msg_a, &mut rng).unwrap();
    assert_eq!(a.finish(&msg_b).unwrap_err(), CpaceError::ConfirmationFailed);
}

#[test]
fn tampered_point_is_rejected() {
    for byte in [1usize, 16, 32] {
        let mut rng = TestRng::new(10 + byte as u64);
        let i = inputs(b"493017", b"ci", b"");
        let (a, mut msg_a) = Initiator::start(&i, &mut rng).unwrap();
        msg_a[byte] ^= 0x04;
        // A changed encoding either fails to decode or is a different point.
        let err = match Responder::respond(&i, &msg_a, &mut rng) {
            Err(e) => e,
            Ok((_, msg_b)) => a.finish(&msg_b).unwrap_err(),
        };
        assert!(matches!(err, CpaceError::InvalidPoint | CpaceError::ConfirmationFailed), "{err:?}");
    }
}

#[test]
fn identity_point_is_rejected_by_both_roles() {
    let i = inputs(b"493017", b"ci", b"");
    let identity_msg = lv_cat(&[&IDENTITY, b""]);
    let mut rng = TestRng::new(20);
    assert_eq!(Responder::respond(&i, &identity_msg, &mut rng).unwrap_err(), CpaceError::InvalidPoint);
    let (a, _) = Initiator::start(&i, &mut rng).unwrap();
    let msg_b = [identity_msg, vec![0u8; TAG_LEN]].concat();
    assert_eq!(a.finish(&msg_b).unwrap_err(), CpaceError::InvalidPoint);
}

#[test]
fn truncated_messages_are_rejected() {
    let i = inputs(b"493017", b"ci", b"ad");
    let mut rng = TestRng::new(21);
    let (_, msg_a) = Initiator::start(&i, &mut rng).unwrap();
    for len in 0..msg_a.len() {
        assert_eq!(
            Responder::respond(&i, &msg_a[..len], &mut rng).unwrap_err(),
            CpaceError::Malformed,
            "len {len}"
        );
    }
    let (b, msg_b) = Responder::respond(&i, &msg_a, &mut rng).unwrap();
    for len in 0..msg_b.len() {
        let mut rng = TestRng::new(21);
        let (a, _) = Initiator::start(&i, &mut rng).unwrap();
        assert_eq!(a.finish(&msg_b[..len]).unwrap_err(), CpaceError::Malformed, "len {len}");
    }
    assert_eq!(b.finish(&[0u8; TAG_LEN - 1]).unwrap_err(), CpaceError::Malformed);
}

#[test]
fn swapped_roles_do_not_confirm() {
    let i = inputs(b"493017", b"ci", b"");
    let mut rng = TestRng::new(30);
    // Two initiators: one's msg_a is not a valid msg_b.
    let (a1, _) = Initiator::start(&i, &mut rng).unwrap();
    let (_, msg_a2) = Initiator::start(&i, &mut rng).unwrap();
    assert_eq!(a1.finish(&msg_a2).unwrap_err(), CpaceError::Malformed);
    // Even with a tag-sized tail it does not confirm.
    let (a1, _) = Initiator::start(&i, &mut rng).unwrap();
    let (_, msg_a2) = Initiator::start(&i, &mut rng).unwrap();
    let forged = [msg_a2, vec![0u8; TAG_LEN]].concat();
    assert_eq!(a1.finish(&forged).unwrap_err(), CpaceError::ConfirmationFailed);

    // The responder's own tag echoed back as the initiator's tag.
    let (a, msg_a) = Initiator::start(&i, &mut rng).unwrap();
    let (b, msg_b) = Responder::respond(&i, &msg_a, &mut rng).unwrap();
    let tb = msg_b[msg_b.len() - TAG_LEN..].to_vec();
    assert_eq!(b.finish(&tb).unwrap_err(), CpaceError::ConfirmationFailed);
    // A responder's msg_b fed to a responder is not a msg_a.
    assert_eq!(Responder::respond(&i, &msg_b, &mut rng).unwrap_err(), CpaceError::Malformed);
    drop(a);
}

#[test]
fn own_inputs_are_checked() {
    let mut rng = TestRng::new(40);
    let msg = lv_cat(&[&IDENTITY, b""]);
    let empty = inputs(b"", b"ci", b"");
    assert_eq!(Initiator::start(&empty, &mut rng).unwrap_err(), CpaceError::EmptyPassword);
    assert_eq!(Responder::respond(&empty, &msg, &mut rng).unwrap_err(), CpaceError::EmptyPassword);
    let short_sid = Inputs { sid: &SID[..MIN_SID_LEN - 1], ..inputs(b"1", b"", b"") };
    assert_eq!(Initiator::start(&short_sid, &mut rng).unwrap_err(), CpaceError::SidTooShort);
    let long_ad = vec![7u8; MAX_AD_LEN + 1];
    let too_long = inputs(b"1", b"", &long_ad);
    assert_eq!(Initiator::start(&too_long, &mut rng).unwrap_err(), CpaceError::AdTooLong);
    assert_eq!(Responder::respond(&too_long, &msg, &mut rng).unwrap_err(), CpaceError::AdTooLong);
}

#[test]
fn largest_ad_round_trips() {
    let ad = vec![0xa5u8; MAX_AD_LEN];
    let i = inputs(b"493017", b"ci", &ad);
    let (a, b) = run(&i, &i, 41).unwrap();
    assert_eq!(a.peer_ad(), &ad[..]);
    assert_eq!(b.peer_ad(), &ad[..]);
}

#[test]
fn debug_output_hides_secrets() {
    let i = inputs(b"493017", b"ci", b"");
    let (a, _) = run(&i, &i, 42).unwrap();
    let shown = format!("{a:?} {i:?}");
    assert!(!shown.contains("493017"));
    let first = format!("{:02x}", a.isk().as_bytes()[0]);
    assert!(shown.contains("redacted"));
    assert!(!shown.contains(&format!("{first}{:02x}", a.isk().as_bytes()[1])));
}
