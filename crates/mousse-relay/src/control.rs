//! Must-fail controls of the relay crate (`checks/phase3.toml`). Each
//! plants one defect for tests; none compiles into a release build.

#[cfg(mousse_control = "relay-persist-allow-set")]
pub use persist::PersistAllowSet;

/// `relay-persist-allow-set` (`phase3.relay-reboot`): the relay keeps the
/// first allow-set each handle ever pushed in its state directory and, after
/// a reboot, applies it as soon as the handle registers again, before the
/// target pushes a fresh one. A reboot then no longer resets admission, and
/// a caller removed before the reboot is admitted again.
#[cfg(mousse_control = "relay-persist-allow-set")]
mod persist {
    use std::collections::HashMap;

    use mousse_net_core::relay::machine::{ConnId, Now, Output, Relay};
    use mousse_net_core::relay::RelayMessage;
    use rand_core::CryptoRng;

    use crate::state::{hex, unhex32, StateDir};

    #[derive(Default)]
    pub struct PersistAllowSet {
        sets: HashMap<[u8; 32], Vec<u8>>,
        handles: HashMap<ConnId, [u8; 32]>,
    }

    impl PersistAllowSet {
        pub fn load(state: &StateDir) -> Self {
            let mut me = Self::default();
            if let Ok(bytes) = std::fs::read(state.control_allow_sets_path()) {
                if let Ok(map) = serde_json::from_slice::<HashMap<String, String>>(&bytes) {
                    for (h, set) in map {
                        if let (Some(h), Some(set)) = (unhex32(&h), unhex(&set)) {
                            me.sets.insert(h, set);
                        }
                    }
                }
            }
            me
        }

        fn save(&self, state: &StateDir) {
            let map: HashMap<String, String> =
                self.sets.iter().map(|(h, s)| (hex(h), hex(s))).collect();
            let _ = std::fs::write(
                state.control_allow_sets_path(),
                serde_json::to_vec(&map).expect("json"),
            );
        }

        #[allow(clippy::too_many_arguments)]
        pub fn after_receive<R: CryptoRng + ?Sized>(
            &mut self,
            state: &StateDir,
            conn: ConnId,
            bytes: &[u8],
            mut outs: Vec<Output>,
            now: Now,
            relay: &mut Relay,
            rng: &mut R,
        ) -> Vec<Output> {
            let mut inject = Vec::new();
            for o in &outs {
                let Output::Send { conn: c, message } = o else {
                    continue;
                };
                match RelayMessage::decode(message) {
                    Ok(RelayMessage::Registered { handle }) => {
                        self.handles.insert(*c, handle);
                        if let Some(set) = self.sets.get(&handle) {
                            inject.push((*c, set.clone()));
                        }
                    }
                    Ok(RelayMessage::AllowSetOk { .. }) if *c == conn => {
                        if let Some(h) = self.handles.get(&conn) {
                            if !self.sets.contains_key(h) {
                                self.sets.insert(*h, bytes.to_vec());
                                self.save(state);
                            }
                        }
                    }
                    _ => {}
                }
            }
            for (c, set) in inject {
                let more = relay.receive(c, &set, now, rng);
                outs.extend(
                    more.into_iter()
                        .filter(|o| !matches!(o, Output::Send { .. })),
                );
            }
            outs
        }
    }

    fn unhex(text: &str) -> Option<Vec<u8>> {
        if text.len() % 2 != 0 {
            return None;
        }
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
            .collect()
    }
}

/// `marker-in-relay-memory` (`phase3.marker`, memory positive control):
/// the relay reads the marker from the file named by
/// `MOUSSE_RELAY_CONTROL_MARKER_FILE` and keeps copies in its heap, so a
/// memory sample of the process must find it. (A file, not the variable
/// itself: the environment sits in process memory too, and the control must
/// be caught for the heap copy.)
#[cfg(mousse_control = "marker-in-relay-memory")]
pub fn keep_marker_in_memory() {
    use std::sync::Mutex;
    static KEPT: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
    if let Some(path) = std::env::var_os("MOUSSE_RELAY_CONTROL_MARKER_FILE") {
        if let Ok(bytes) = std::fs::read(path) {
            for _ in 0..16 {
                KEPT.lock().expect("kept").push(bytes.clone());
            }
        }
    }
}

/// Debug builds only: append each spliced message the relay forwards to the
/// file named by `MOUSSE_RELAY_TAP`, the relay's decrypted view of both
/// legs for `phase3.marker`. Release builds have no tap.
#[cfg(debug_assertions)]
pub fn tap(bytes: &[u8]) {
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    static TAP: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();
    let tap = TAP.get_or_init(|| {
        let path = std::env::var_os("MOUSSE_RELAY_TAP")?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
            .map(Mutex::new)
    });
    if let Some(f) = tap {
        let _ = f.lock().expect("tap").write_all(bytes);
    }
}
