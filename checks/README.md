# Owner checks

`mousse-check <phase>` runs this machine's checks and their must-fail controls, reads signed results from other devices, and prints one row per check × target cell with an overall verdict. It exits 0 only when the phase passes.

    cargo run -p mousse-check -- phase0            # run local checks, then the table
    cargo run -p mousse-check -- report phase0     # the table from stored runs, no running
    cargo run -p mousse-check -- phase0 --full     # details not cut

Set `CARGO_TARGET_DIR` outside the checkout: build output inside it makes the tree dirty.

## Statuses

| Status | Meaning |
| --- | --- |
| PASS | The run passed **and** every must-fail control printed FAIL, for the build under test, on a clean tree. |
| FAIL | The run failed, a control did not fail, a control printed no FAIL line (build error, missing feature), a control failed for another reason than its `expect_reason`, the check has no control, a control is marked missing, or the check is deferred without permission. |
| INCOMPLETE | No result for the build under test and the check's current configuration yet, a placeholder, or a dirty tree. |
| DEFERRED | The phase's `[defer]` table allows this check to be deferred, and it is. |
| ATTESTED | Someone recorded a manual step. Counts only for checks marked `manual`; on an automated check it is shown but blocks the verdict. |

The phase passes when every cell is PASS, an allowed DEFERRED, or an ATTESTED manual step, and no result file was tampered with.

## Build under test

`<commit>[-dirty]+<profile>`. The commit is the last one that changed anything outside `checks/`, so committing results, attestations, manifests or the device list does not make results stale. Any other change, including a new commit to the code, needs fresh results.

Evidence must also match the check's current configuration. Every local run record and signed result carries `config`, a SHA-256 digest of what decides what the run proves: the judge, `min_tests`, the markers, the profile, the matrix cases, the target's `[[check.local]]` commands (`command`, `cwd`, `env`) and, for a control, its `command`, `args`, `env` and `expect_reason`. A committed change to any of these makes that check's old results INCOMPLETE until it runs again. `title`, `plan`, `breaks` and `device_steps` are descriptions and do not count. Uncommitted changes outside `checks/results/` and `checks/runs/` make the tree dirty; no cell passes on a dirty tree without `--allow-dirty` (shown in the table and the verdict).

## Manifests (`<phase>.toml`)

Top level: `phase`, `title`, `plan`, optional `profile` (device results must carry it), and `[defer]`: check id → reason, the only checks allowed to end DEFERRED.

Each `[[check]]`:

| Field | |
| --- | --- |
| `id` | `<phase>.<name>` |
| `title`, `plan` | what it proves, and the plan item |
| `targets` | the cells; every one must pass |
| `judge` | `cargo-test` (default), `marker`, or `matrix` |
| `min_tests` | `cargo-test`: the normal run must pass at least this many tests |
| `pass_marker`, `fail_marker` | default `PASS <id>` / `FAIL <id>`; must be a whole line |
| `profile` | profile results must carry. A local run records the profile its command actually builds with, read from the cargo command (`--release`, `-r`, `--profile <name>`; none means `debug`; `unknown` for a command that is not `cargo build`, `run`, `test` or `bench`). With `profile` set, every local command and control must be a cargo command with that profile, or the manifest is refused |
| `cross_machine` | one machine dials another: each result must name the host's build in `extra.host_build`, and both builds must be the build under test |
| `placeholder` | not wired yet: cells are INCOMPLETE and the phase run skips it (`run` still runs it) |
| `deferred` | deferred; only counts if `[defer]` lists it |
| `manual`, `steps` | a manual step; cells can only be ATTESTED |
| `device_steps` | how a device produces its result, shown while the cell is INCOMPLETE |
| `timeout_secs` | per run, default 3600 |
| `[[check.local]]` | `target`, `host` (`windows-x86_64`, `macos-aarch64`, `linux-x86_64`, ...), `command`, optional `cwd`, `env`, `placeholder`. Runs when the kit is on that host. `{root}`, `{out}` (a fresh folder per run) and `{build}` are replaced; `MOUSSE_BUILD_ID` is set. |
| `[[check.control]]` | `name`, `breaks` (what is broken), and `args` (appended), `env` (added) or `command` (replaces). `missing = "reason"` while the control does not exist: the check is FAIL until it does. `expect_reason = "<word>"`: the control must fail for this reason (see below). |
| `[check.matrix]` | `providers`, `providers_for` (per target), `legacy_results` (unsigned files shown but never counted) |

Judges:

- `cargo-test`: pass = exit 0, at least one `test result:` line, none failed, at least `min_tests` passed. A control works only if it exits non-zero with a `test result: FAILED` line and at least one failed test, and runs the same number of tests as the normal run (use `--no-fail-fast`). A missing cargo feature or a build error is "no FAIL line", which is FAIL.
- `marker`: pass = exit 0 and the pass line, no fail line. A control works only if it exits non-zero and prints the fail line.
- `matrix`: as `marker`, and the run must write a PASS file for every ordered provider pair into `{out}` (spec/matrix/targets.md format).

A control with `expect_reason` must also show that reason. A local run must print it on the FAIL line, as `FAIL <id> reason=<word>`; a device result must carry it as `extra.reason` (or `reason=<word>` in `details`). A control that fails for another reason, or gives none, is FAIL: something other than the named defect broke the run.

## Local run records

`checks/runs/` (not committed) holds this machine's last run of each part. A record names its check, target, part, build, `host` (`<os>-<arch>`), `runner` (the `[[check.local]]` entry that produced it) and `config`. Records count only for a cell with a `[[check.local]]` entry for this machine's host, and only if they name that host and entry. Every other cell, including every device-only cell, counts only signed results.

## Results from other machines

Device results are JSON payloads `{check, target, case?, control?, build, platform, outcome, details, time, device, config, extra?}` signed with the device's P-256 key (ECDSA/SHA-256, raw r‖s, over `"mousse-check-result-v1\0" ‖ payload`). The file keeps the exact signed payload text. The kit checks the key is in `devices.toml`, the payload names that device, the device is trusted for that target, the build is the build under test and `config` matches the check's current configuration. The digest is recorded when the result is produced, never when it is signed. `run --sign-with` records it from the run. A device that produces results any other way (the helper's slice check, matrix logs, a phone) first runs `mousse-check config-digest <check> --target <cell> [--control <name>]`, then passes the printed digest as a `config` field in the result file or as `sign --config <digest>`. `sign` refuses a result without one, refuses one `--config` for results from more than one run, and warns when the digest differs from this checkout's manifest (such a result counts only for that configuration).

`sign` also keeps these top-level fields of a result file in `extra`: `reason`, `host_build` and `caller_build` (and `reason` inside an object `details`). For a `cross_machine` check, `build` is the caller's build and `extra.host_build` the host's; both, and `extra.caller_build` if present, must be the build under test. A result without `extra.host_build` does not count.

A cell from devices passes when, for this build, every case (one, or every matrix pair) has a PASS, no result says FAIL, and every control has at least one result and all of them say FAIL. A changed or forged file is listed as TAMPERED and blocks the verdict.

    # on the device, once
    mousse-check device keygen --out ~/.mousse/device.key
    # on the evaluating checkout, then commit devices.toml
    mousse-check device add --name mac-mini --key <public hex> --targets aarch64-apple-darwin,x86_64-apple-darwin

    # a machine that can run the check itself
    mousse-check run phase0.crypto-matrix --target aarch64-apple-darwin --sign-with ~/.mousse/device.key
    mousse-check run phase0.crypto-matrix --target aarch64-apple-darwin --sign-with ~/.mousse/device.key --control

    # output produced elsewhere (a phone, a browser page): result JSON, matrix files or MATRIX_RESULT logs.
    # Record the configuration before each run, sign with it after.
    mousse-check config-digest phase0.crypto-matrix --target aarch64-apple-ios            # prints <digest>
    mousse-check config-digest phase0.crypto-matrix --target aarch64-apple-ios --control break-pin
    mousse-check sign --device-key ~/.mousse/device.key --config <digest> phone-run.log
    mousse-check sign --device-key ~/.mousse/device.key --config <control digest> --control break-pin phone-control.log

Signed files go to `checks/results/<device>/`; commit them.

## Manual steps

    mousse-check attest phase0.design-review --target session-cert --note "reviewed by X, link"

Written to `checks/results/attest/` with who, when and the build. ATTESTED, never PASS.

## The crypto matrix files in spec/matrix/results

They are unsigned and from an older build, so they are shown in the details but count as INCOMPLETE. Anyone can edit an unsigned file, and the kit can re-run the Windows cell itself in about a minute; other cells re-run signed with the commands above.
