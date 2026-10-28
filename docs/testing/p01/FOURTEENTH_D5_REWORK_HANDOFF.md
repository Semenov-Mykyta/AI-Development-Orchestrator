# Fourteenth Independent D5 Rework — Developer Handoff

**Scope:** P01 D5 test-oracle candidate only; no P01 implementation, normative edits, production access, deploy or merge.

Previous rejected SHA: `4455a50f3a6098a01de164894807911bb1d59a89`
Normative Base SHA: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`

## FOURTEENTH-D5-050 — OS measurement and receipt chronology

`_verify_raw_os_probe_artifact()` requires each source-specific syscall monotonic timestamp to fall in the interval between runner-issued challenge_start_ns and signed attester receipt issued_monotonic_ns. The positive synthetic fixture now issues its receipt **after** constructing both primary OS-probe artifacts. A negative test re-signs an impossibly early issue timestamp and requires NOT_CHECKED.

## FOURTEENTH-D5-051 — read-only evidence before/after actual bytes

The observer primary artifact must embed canonical, bounded `write_denial_state` with `before_b64`, `after_b64` and a test-only `/synthetic/` target. The verifier decodes and hashes the exact bytes; both must be identical and match the two signed metadata SHA-256 claims. Mutating both metadata digests to the same other SHA now fails closed. Primary witness digest and independent kernel-audit sensor event correlation remain mandatory. Real OS file and broker read-only policy attestation is OQ-09/A NOT_CHECKED, not demonstrated by synthetic bytes.

## FOURTEENTH-D5-052 — independent kernel audit source

An attester-signed JSON claim or signed artifact byte digest **cannot by itself prove kernel provenance**.

The owner-signed policy now requires a fourth, distinct key for the kernel audit sensor, its absolute public-key path, deployment SHA-256 and sensor ID. The runner loads its pinned key independently. The live attester response must also contain a separately Ed25519-signed `kernel_audit` envelope covering:

- nonce, run, Git SHA, command digest, owner-policy SHA and boot ID;
- pinned audit deployment and immutable audit identity;
- exact SHA-256 set for all primary signing-interface and observer OS probes;
- individually recorded `kernel_syscall_events` containing roles, UID/GID, syscall operation, errno, target, monotonic timestamps, namespace ID and MAC profile;
- independently discovered complete signing endpoint inventory;
- explicit Linux audit-netlink origin and zero lost events.

Verification compares every independently signed audit event to every canonical primary probe event and rejects missing/unattributed/extra endpoints, mismatched digests, wrong keys, forged signatures and event losses. No audit authority => NOT_CHECKED.

**Critical scope limitation:** A test-only Ed25519 key can still sign synthetic events, so a cryptographic unit PASS does not prove those syscalls happened. Actual Linux audit collection, independence of sensor from attester/collector/SUT, protection of private signing keys and enumeration of hidden brokers must be inspected and tested at OQ-09/A before any real AC PASS. No installed sensor is claimed.

## FOURTEENTH-D5-053 — provenance precedes normative AC result

`verify_independent_proofs(..., evaluate_expected=False)` authenticates trusted witness/run/measurement provenance without prematurely evaluating expected observations. Existing direct calls retain `evaluate_expected=True` for backward compatibility. A separate `verify_normative_measurements(case, observations, run)` performs quota/reconciliation/history checks and normative AC comparisons.

In `test_p01_acceptance.py` the mandated order is:
1. Verify independent observer source signatures;
2. Verify HMAC-protected independent witnesses with `evaluate_expected=False`;
3. Validate independent monitor ready/stop `execve` closure;
4. Only then compare normative AC values. An invalid execution trace must yield NOT_CHECKED even if AC measurements are wrong.

## Regression evidence and remaining gates

New file: `tests/test_p01_fourteenth_review_regressions.py` with positive and negative cases for 050–053, including signed-but-impossible chronology, equal-but-forged before/after digests, missing/wrong sensor signatures and event inventories, and FAIL/NOT_CHECKED classification.

Locally tested **the recovered D5 subset**: `38 passed, 1 skipped` across twelfth, thirteenth and fourteenth regression suites; `python -m compileall -q tests` exit 0. The skip is the static acceptance-source order test because the full acceptance file is not present in the locally reconstructed subset; the staged exact GitHub acceptance blob was separately checked for the correct control-flow marker order. These results do **not** establish a full exact-SHA project pytest PASS. Exact published source SHA for the newly edited Python files is independently checkable using GitHub Git blobs.

The frozen `P01_ORACLES.json` and normative documents remain unchanged. The complete 27 AC / 63 scenario matrix remains a candidate. Authentic owner trust provisioning, approved OQ-09/A Linux kernel audit sensor, independent observer/attester, real process closure, Git/CI/off-node evidence, runtime P01 and user owner inspection remain NOT_CHECKED. D5 = REVIEW_PENDING; P01 = NOT_COMPLETED; P02 = BLOCKED. No merge/deploy.
