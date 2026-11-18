# Phone spikes (Phase 0, spikes 3 and 4)

Two checks run inside real iOS and Android host apps:

- **`phase0.phone-lifecycle` (spike 4).** A UniFFI library in which Rust owns a tokio runtime. Swift sees `async` methods and Kotlin sees `suspend` methods. The script tests start, stop, dial, cancel and bounded event batches, and shows that cancelling leaks no socket or task.
- **`phase0.phone-byte-path` (spike 3).** A Rust WebSocket server on `127.0.0.1` with strict Host and Origin checks and a per-launch token. The app's WebView pushes terminal-like small writes and a 32 MiB file each way through it.

This directory is its own Cargo workspace, kept apart from the main workspace.

## Layout

| Path | What |
| --- | --- |
| `rust/` | `mousse-phone-spike`: the engine (`engine.rs`), the byte path server and probes (`bytepath.rs`), result reports (`report.rs`), and the OS socket count (`fds.rs`). Built as `staticlib` for iOS, `cdylib` for Android, and `lib` for host tests. |
| `bindgen/` | `uniffi-bindgen` 0.32.2, run in library mode on the built library. |
| `web/bytepath.html` | The byte path page that both apps load. |
| `ios/` | SwiftUI host app (iOS 15, Swift 6 language mode, strict concurrency). It is built with `swiftc` and has no Xcode project. |
| `android/` | Kotlin host app (Gradle, AGP 8.13, minSdk 24). |
| `scripts/collect-results.mjs` | Reads the app's `MOUSSE_RESULT` lines and writes the result files. It exits 1 when an outcome is not the expected one: PASS for normal runs, FAIL for controls. |
| `results/` | One JSON file per check and target: `{check, target, outcome, build, details}`. Must-fail controls go in `results/controls/`. |

`build` is the git short sha of this directory, plus `-dirty` if there are uncommitted changes, plus the Cargo profile, for example `b7bdf85+release`.

## Lifecycle API (spike 4)

```
Engine(config)                        config: event capacity, worker threads, break mode
start() / stop() / isRunning()        stop() cancels everything and shuts the runtime down (2 s cap)
startEchoServer() -> port             local TCP echo peer for the script
dial(addr) -> id                      TCP connect plus one 1 KiB echo, runs on the Rust runtime
waitDial(id) async -> EchoResult      throws Cancelled, Stopped, Timeout, Io, ...
cancel(id) -> Bool
dialState(id), status()               live dials, engine-held sockets, alive tasks, dropped events
nextEvents(max, timeoutMs) async -> EventBatch   at most `max` events; plus the dropped total
```

Design points the spike settles:

- **Rust owns the runtime.** It is a multi-thread tokio runtime that `start` creates and `stop` shuts down. Each async method spawns its work onto that runtime and awaits the `JoinHandle`. The foreign executor (Swift's cooperative pool or a Kotlin dispatcher) therefore never polls tokio I/O.
- **Cancellation is a token tree.** There is one root `CancellationToken` and a child token per dial. `cancel(id)` fires the child token and the dial resolves as `Cancelled` straight away. `stop()` fires the root token, so pending waits resolve as `Stopped`.
- **Dropping a wait cancels the dial.** If the foreign future is dropped, a drop guard cancels the dial and aborts the helper task.
- **Swift task cancellation needs a small shim.** UniFFI 0.32.2's Swift async wrapper does not forward `Task` cancellation: it awaits with `withUnsafeContinuation`. The app wraps the wait in `withTaskCancellationHandler { waitDial(id) } onCancel: { cancel(id) }` (`Engine.waitDialCancellable` in `ios/Sources/Lifecycle.swift`). Product bindings should generate this shim for every cancellable call.
- **Kotlin needs no shim.** UniFFI's Kotlin wrapper uses `suspendCancellableCoroutine` and frees the Rust future on cancellation, so the drop guard does the work.
- **Events go through a bounded queue.** Events are queued with `try_send`. When the queue is full, events are dropped and counted, and nothing blocks the engine. `nextEvents` returns batches of at most `max` events.
- **Leaks are checked four ways.**
  - Engine-held sockets.
  - Live dials.
  - Tokio alive tasks.
  - The process's socket count (`/dev/fd` on iOS, `/proc/self/fd` on Android), compared with a baseline taken after the count settles at launch.

One iteration of the script runs these steps:

1. Start, then dial the echo server.
2. Dial an unroutable address, check that the dial is still pending, then cancel it. The cancel must resolve within 250 ms.
3. Cancel a second pending dial by cancelling the Swift Task or Kotlin Job.
4. Check that no dials or extra tasks are live.
5. Check events:
   - they come in bounded batches;
   - the expected events arrive;
   - an overflow is counted.
6. Stop, check that a pending dial resolved, and check that a dial after stop is refused.
7. Check that the process socket count is back to the baseline.

The default unroutable address is `10.255.255.1:9`. If that address fails fast on a network, the script tries the next one: `192.0.2.1`, `198.51.100.1`, then `203.0.113.1`. It records each skip in `details.blackholeSkips`.

## Byte path (spike 3)

- **Server.** It listens on `127.0.0.1:<random port>` and accepts only `/bytes?t=<token>`. The token is 32 random bytes, hex-encoded, compared in constant time, and new at every launch. `Host` must be exactly `127.0.0.1:<port>`. `Origin` must be exactly the app's page origin. Anything else is refused with 403 before the upgrade.
- **Page origins.**
  - iOS serves the page from a `WKURLSchemeHandler` at `mousse-app://localhost`.
  - Android serves it from `shouldInterceptRequest` at `https://localhost`.
  - Neither app opens a page port.
- **What the page does.**
  1. Tries a wrong token, which must be refused.
  2. Sends 2000 sequential small echoes (p50/p95), then a burst of 5000 writes.
  3. Uploads 32 MiB, paced by `bufferedAmount`. The server checks every byte.
  4. Downloads 32 MiB and checks every byte.
- **Raw probes from Rust.**
  - `valid` must get 101.
  - Each of these must not get 101: `wrong-token`, `missing-token`, `wrong-host`, `localhost-host`, `missing-host`, `wrong-origin`, `null-origin`, `missing-origin`.
- **Budgets.** Terminal echo p95 ≤ 16 ms. File transfer ≥ 10 MB/s, measured on the slower of upload and download.

## Must-fail controls

| Control | What breaks | Must fail on |
| --- | --- | --- |
| `--control cancel` | `cancel()` and the drop guard do nothing | `cancel-pending-dial`, `task-cancel-resolves` (iOS), `no-live-dials-after-cancel`, `no-task-leak-before-stop`, `events-expected` |
| `--control token` | the server skips the token check | `page-wrong-token-refused`, `probe-wrong-token`, `probe-missing-token`, `server-refused-page-wrong-token` |

## Results

All rows use build `b7bdf85+release`. Lifecycle results cover 20 iterations, and the cancel latencies are p50 / p95.

| Target | Lifecycle | Cancel latency | Byte path | Echo p50 / p95 | Upload / download | Controls |
| --- | --- | --- | --- | --- | --- | --- |
| iOS Simulator 26.3.1 (iPhone 16, arm64) | PASS | 0.4 / 2.1 ms | PASS | 0 / 1 ms (WebKit timer step is 1 ms) | 381 / 599 MB/s | cancel FAIL, token FAIL |
| Android emulator API 35, arm64-v8a, WebView 124 | PASS | 0.8 / 2.5 ms | PASS | 0.2 / 0.8 ms | 283 / 125 MB/s | cancel FAIL, token FAIL |
| Android emulator API 24 (7.0), arm64-v8a, WebView 52 | PASS | 0.8 / 1.2 ms | INCOMPLETE: WebView 52 is below the floor of 60 | – | – | cancel FAIL |
| iPhone, iOS 15 | INCOMPLETE | | INCOMPLETE | | | |
| iPhone, latest iOS | INCOMPLETE | | INCOMPLETE | | | |
| Android phone (arm64-v8a) | INCOMPLETE | | INCOMPLETE | | | |
| Android emulator x86_64 | INCOMPLETE | | INCOMPLETE | | | |

Simulator and emulator numbers show that the design works. They are not phone performance; the phone cells settle that.

The byte path also passes on Android 7.0 once that WebView updates past 60; Android 7 receives WebView updates up to version 119. The API 24 emulator image ships WebView 52, which cannot parse the page because it has no `async` functions. The app reports the cell as INCOMPLETE rather than FAIL because it is below the supported floor. Product code would apply the same floor at runtime.

## Android minimum API and ABIs

- **minSdk 24 (Android 7.0).**
  - It matches Capacitor 8's minimum, so the phone app adds no stricter floor.
  - The lifecycle check passes 20/20 on an API 24 emulator.
  - The Rust library links against API 24 (`MIN_API`).
  - Below 24 there is no Capacitor support, and devices that old have no current WebView.
  - The byte path needs WebView 60 or newer, which the app checks at runtime.
- **ABIs arm64-v8a and x86_64.**
  - arm64-v8a covers phones in use and emulators on Apple silicon.
  - x86_64 covers emulators on Intel and Linux CI.
  - 32-bit ABIs (armeabi-v7a, x86) are dropped. Play has required 64-bit since 2019, and Android 7+ phones that run only 32-bit are a small, shrinking share.
  - The release library is about 11 MB per ABI, unstripped; stripping is a release-packaging task.

## What is missing

- **Physical phones.** An iPhone on iOS 15, an iPhone on the latest iOS, and an Android arm64 phone. Commands are below.
- **iOS 15 simulator runtime.** It is not installed on the build Mac, which has only iOS 26.3. The binary is built with `minos 15.0`. A 6+ GB runtime download was skipped, because the physical iOS 15 cell covers the same ground.
- **x86_64 Android emulator.** It cannot run on Apple silicon. The x86_64 `.so` builds and is packaged in the APK.
- **Device signing for iOS.** `ios/build.sh device` compiles and links for `arm64-apple-ios15.0`. Installing it needs a signing identity and a provisioning profile.
- **Android `socket_fd_list`.** Recent Android versions block app access to `/proc/net`, so leak notes there show fd numbers only.

## Commands

Prerequisites:

- Rust 1.96 or newer, with these targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-linux-android`, `x86_64-linux-android`.
- Node 18 or newer.
- For iOS: Xcode.
- For Android: a JDK 17 or 21, and the Android SDK with an NDK (r28 was used).

`CARGO_TARGET_DIR` defaults to `spikes/phone/target`.

Host tests:

```sh
cd spikes/phone
cargo test -p mousse-phone-spike
```

### iOS Simulator

```sh
ios/run-sim.sh --runs 20                                  # all checks, must PASS
ios/run-sim.sh --runs 5 --check lifecycle --control cancel  # must FAIL
ios/run-sim.sh --check byte-path --control token            # must FAIL
# another runtime: --runtime com.apple.CoreSimulator.SimRuntime.iOS-15-5 (xcrun simctl list runtimes)
```

### Physical iPhone

The phone must be unlocked and trusted. iOS 16 and later also need Developer Mode. You need an Apple Development identity and a provisioning profile for `work.mousse.netspike`; to use another app id, set `BUNDLE_ID`.

```sh
export SIGN_IDENTITY="Apple Development: Name (TEAMID)"
export PROVISIONING_PROFILE=~/Downloads/netspike.mobileprovision

# latest iOS (17+): devicectl ships with Xcode
xcrun devicectl list devices
ios/run-device.sh --device <udid> --runs 20
ios/run-device.sh --device <udid> --runs 5 --check lifecycle --control cancel
ios/run-device.sh --device <udid> --check byte-path --control token

# iOS 15 (and 16): devicectl does not drive these; use ios-deploy (brew install ios-deploy)
ios-deploy -c
ios/run-device.sh --device <udid> --tool ios-deploy --runs 20
ios/run-device.sh --device <udid> --tool ios-deploy --runs 5 --check lifecycle --control cancel
ios/run-device.sh --device <udid> --tool ios-deploy --check byte-path --control token
```

Results are written as `results/<check>__ios-<version>.json`. The app also keeps a copy in its `Documents/results/`.

### Android emulator

```sh
export ANDROID_HOME=~/Library/Android/sdk ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358
android/build.sh                                          # arm64-v8a and x86_64 APK
android/run-emu.sh --image "system-images;android-35;google_apis;arm64-v8a" --runs 20
android/run-emu.sh --image "system-images;android-35;google_apis;arm64-v8a" --runs 5 --check lifecycle --control cancel
android/run-emu.sh --image "system-images;android-35;google_apis;arm64-v8a" --check byte-path --control token
android/run-emu.sh --image "system-images;android-24;default;arm64-v8a" --runs 20
```

`run-emu.sh` boots a throwaway headless emulator and deletes it after the run. The system image must already be installed (`sdkmanager "<image>"`).

### Android phone

Turn on USB debugging and accept the host's key. Then:

```sh
adb devices
ANDROID_SERIAL=<serial> android/run.sh --runs 20
ANDROID_SERIAL=<serial> android/run.sh --runs 5 --check lifecycle --control cancel
ANDROID_SERIAL=<serial> android/run.sh --check byte-path --control token
```

Results are written as `results/<check>__android-<api>-<abi>.json`. If a cellular or office network answers the default unroutable address quickly, pass `--unroutable <ip:port>` with an address that drops packets silently.
