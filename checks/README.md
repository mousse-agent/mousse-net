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
| FAIL | The run failed, a control did not fail, a control printed no FAIL line (build error, missing feature), the check has no control, a control is marked missing, or the check is deferred without permission. |
| INCOMPLETE | No result for the build under test yet, a placeholder, or a dirty tree. |
| DEFERRED | The phase's `[defer]` table allows this check to be deferred, and it is. |
| ATTESTED | Someone recorded a manual step. Counts only for checks marked `manual`; on an automated check it is shown but blocks the verdict. |

The phase passes when every cell is PASS, an allowed DEFERRED, or an ATTESTED manual step, and no result file was tampered with.

## Build under test

`<commit>[-dirty]+<profile>`. The commit is the last one that changed anything outside `checks/`, so committing results, attestations, manifests or the device list does not make results stale. Any other change, including a new commit to the code, needs fresh results. Uncommitted changes outside `checks/results/` and `checks/runs/` make the tree dirty; no cell passes on a dirty tree without `--allow-dirty` (shown in the table and the verdict).

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
| `profile` | profile device results must carry |
| `placeholder` | not wired yet: cells are INCOMPLETE and the phase run skips it (`run` still runs it) |
| `deferred` | deferred; only counts if `[defer]` lists it |
| `manual`, `steps` | a manual step; cells can only be ATTESTED |
| `device_steps` | how a device produces its result, shown while the cell is INCOMPLETE |
| `timeout_secs` | per run, default 3600 |
| `[[check.local]]` | `target`, `host` (`windows-x86_64`, `macos-aarch64`, `linux-x86_64`, ...), `command`, optional `cwd`, `env`, `placeholder`. Runs when the kit is on that host. `{root}`, `{out}` (a fresh folder per run) and `{build}` are replaced; `MOUSSE_BUILD_ID` is set. |
| `[[check.control]]` | `name`, `breaks` (what is broken), and `args` (appended), `env` (added) or `command` (replaces). `missing = "reason"` while the control does not exist: the check is FAIL until it does. |
| `[check.matrix]` | `providers`, `providers_for` (per target), `legacy_results` (unsigned files shown but never counted) |

Judges:

- `cargo-test`: pass = exit 0, at least one `test result:` line, none failed, at least `min_tests` passed. A control works only if it exits non-zero with a `test result: FAILED` line and at least one failed test, and runs the same number of tests as the normal run (use `--no-fail-fast`). A missing cargo feature or a build error is "no FAIL line", which is FAIL.
- `marker`: pass = exit 0 and the pass line, no fail line. A control works only if it exits non-zero and prints the fail line.
- `matrix`: as `marker`, and the run must write a PASS file for every ordered provider pair into `{out}` (spec/matrix/targets.md format).

## Results from other machines

Device results are JSON payloads `{check, target, case?, control?, build, platform, outcome, details, time, device, extra?}` signed with the device's P-256 key (ECDSA/SHA-256, raw r‖s, over `"mousse-check-result-v1\0" ‖ payload`). The file keeps the exact signed payload text. The kit checks the key is in `devices.toml`, the payload names that device, the device is trusted for that target, and the build is the build under test.

A cell from devices passes when, for this build, every case (one, or every matrix pair) has a PASS, no result says FAIL, and every control has at least one result and all of them say FAIL. A changed or forged file is listed as TAMPERED and blocks the verdict.

    # on the device, once
    mousse-check device keygen --out ~/.mousse/device.key
    # on the evaluating checkout, then commit devices.toml
    mousse-check device add --name mac-mini --key <public hex> --targets aarch64-apple-darwin,x86_64-apple-darwin

    # a machine that can run the check itself
    mousse-check run phase0.crypto-matrix --target aarch64-apple-darwin --sign-with ~/.mousse/device.key
    mousse-check run phase0.crypto-matrix --target aarch64-apple-darwin --sign-with ~/.mousse/device.key --control

    # output produced elsewhere (a phone, a browser page): result JSON, matrix files or MATRIX_RESULT logs
    mousse-check sign --device-key ~/.mousse/device.key phone-run.log
    mousse-check sign --device-key ~/.mousse/device.key --control break-pin phone-control.log

Signed files go to `checks/results/<device>/`; commit them.

## Manual steps

    mousse-check attest phase0.design-review --target session-cert --note "reviewed by X, link"

Written to `checks/results/attest/` with who, when and the build. ATTESTED, never PASS.

## The crypto matrix files in spec/matrix/results

They are unsigned and from an older build, so they are shown in the details but count as INCOMPLETE. Anyone can edit an unsigned file, and the kit can re-run the Windows cell itself in about a minute; other cells re-run signed with the commands above.
