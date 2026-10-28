# D5 Full-Suite Regression Fixture Rework — Developer Handoff

**Scope:** P01 D5 legacy tests only, after the first independent full exact-SHA run.

**Failed independent run SHA:** `030f6fd416cee607c6e775b9767c237b6e6aef20`
**Normative base:** `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`

## Independently reported first full run

Isolated Ubuntu 24.04 VPS, Python 3.12.3, pytest 7.4.4, temporary nonprivileged user in restricted offline systemd sandbox:

- Complete D5 regression suite: **268 PASS, 4 FAIL, 15 SKIP**; pytest exit 1.
- `pytest --collect-only` acceptance: **63 collected**, exit 0.
- Acceptance-file `ast.parse()`: PASS, exit 0.
- `compileall` of tests: PASS, exit 0.
- Last-three-round regressions 17–19: **83 PASS, 2 SKIP**, exit 0.
- Runtime acceptance P01 intentionally NOT RUN because OQ-09/A sandbox is not separately approved.

These are user-provided independent run results for the **old** SHA, not tests run by Developer on this new commit.

## Four targeted test-only changes

1. `tests/test_p01_second_review_regressions.py::test_new_d5_016_proof_must_bind_sha_command_returncode_and_run_id`: remove brittle text equality checking for `json.loads(proof.path.read_bytes())`. Construct valid synthetic, observer-signed/HMAC-pinned evidence using the existing nineteenth-review test helper; mutate separately Git SHA, run ID, command digest, returncode and start ticks; recompute valid HMAC and assert `NOT_CHECKED`. Verify the unmodified positive fixture is accepted.

2. `tests/test_p01_third_review_regressions.py::test_third_018_offnode_backup_order_not_just_boolean`: exercise the existing normative backup-order gate using a synthetic `TestRun` and unchanged frozen `AC-N-15.2` scenario. Positive case has actual ordered sequence and matching backup digest/receipt; reversed or equal order, bool sequence, incorrect backup SHA and missing receipt must give `NOT_CHECKED`. Do **not** demand that the gate remain textually within `verify_independent_proofs`; it was deliberately moved to `verify_normative_measurements` after execution closure.

3. `tests/test_p01_third_review_regressions.py::test_third_019_untrusted_self_approved_collector_denied`: extend existing synthetic owner-signed policy fixture with all current mandatory `oqa_*` and `readonly_observer_*` keys from the twelfth-review test-only fixture. Keep the forged owner signature rejection and add a correctly owner-signed negative missing the mandatory audit-sensor key digest.

4. `tests/test_p01_eleventh_review_regressions.py::test_045_owner_signed_policy_requires_separate_roles_and_guard`: likewise complete the synthetic OQ-09/A policy fixture while keeping all role separation / guard negative cases; add an owner-signed negative with missing audit-sensor ID.

## Constraints and verification

- **No changes** to `tests/p01_probe.py`, `tests/p01_oqa_attestation.py`, `tests/test_p01_acceptance.py`, normative documents or frozen `P01_ORACLES.json`.
- No real attester, kernel sensor, monitor, owner root, private credentials, OQ-09/A privileged runner, or P01 runtime acceptance are provided.
- Developer verified changed test source against previous exact GitHub blobs and published through GitHub Git tree on the feature branch. The **new** exact-SHA full pytest has **not** been executed by Developer: status NOT_CHECKED until independently rerun.
- The original 15 skips require `pytest -rs` details; do not infer privilege/dependency reasons without measured reports. An approved isolated privileged test environment may be required for root-only OS probes, but do not escalate on production VPS.

## Rerun requirement

On a **separate permitted offline test sandbox**, fetch the NEW exact SHA and independently execute the same complete regression suite, acceptance collection, acceptance ast.parse and compileall. Record all exit codes, PASS/FAIL/SKIP counts, reasons for each SKIP (`pytest -rs`), exact Git HEAD and clean git status. Do not run 63 runtime acceptance scenarios without separate OQ-09/A authorization.

**D5 = REVIEW_PENDING / CHANGES_REQUIRED until independent review; P01 NOT_COMPLETED; P02 BLOCKED; no merge or deploy.**
