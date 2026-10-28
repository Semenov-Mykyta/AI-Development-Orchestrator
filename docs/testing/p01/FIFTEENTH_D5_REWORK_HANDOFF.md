# Fifteenth D5 Rework — Developer Handoff

**Scope:** P01 D5 oracle harness only. No P01 application, normative changes, production access, merge, deploy, or runtime AC PASS.

Rejected HEAD: `81327de39d651f1bebaf1241758b25b8158f765b`
Normative Base: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`

## FIFTEENTH-D5-054 — acceptance syntax / positive path

The old `tests/test_p01_acceptance.py` Git blob held **two literal backslash-n byte pairs** outside strings, at the import of `verify_normative_measurements` and `evaluate_expected=False` call. Both have been replaced with real line feeds. The original provenance order remains:

1. Independent observer signatures;
2. HMAC/witness validation with `evaluate_expected=False`;
3. Independent signed kernel execution closure;
4. Normative evaluation, including possible AC `FAIL`.

`test_p01_fifteenth_review_regressions.py` now uses `ast.parse()` on the **actual sibling acceptance source** and checks that no literal backslash-n remains; the test must execute without SKIP when a complete Git checkout is available.

## FIFTEENTH-D5-055 — kernel-audit capture window

`verify_oqa_receipt()` now requires **each** recorded kernel syscall event to have a plain integer monotonic timestamp inside the separately signed sensor interval:

`capture_started_ns <= kernel_event_timestamp <= capture_stopped_ns`.

This is in addition to attester issue-time checks, exact event-by-event comparison with primary OS artifacts and a valid independent kernel-audit signature. Positive cases cover two distinct synthetic timestamps from different sources; negative cases re-sign early-stop and late-start sensor windows using a valid **test** audit key.

## FIFTEENTH-D5-056 — exact kernel lost-event counter type

The kernel-audit receipt now requires `type(event_loss_count) is int` and `event_loss_count == 0`; Python bool or float equality with numeric zero no longer qualifies. Synthetic negative regression cases include `False`, `0.0`, negative and positive integers, `None`, string zero, `True` and a missing field.

## Evidence

- The new tests were first executed against the previous attestation source: **5 FAIL**, demonstrating bugs 055/056.
- After the change, the locally reconstructed test subset produced **51 passed, 2 skipped** across twelfth–fifteenth regression files; `python -m compileall -q tests` exit 0.
- The two local skips are source-dependent tests requiring `tests/test_p01_acceptance.py`, which is not part of the locally reconstructed subset. The full, corrected acceptance source was derived directly from the exact GitHub old HEAD and published as a Git blob; the Reviewer must independently compile it from a complete exact new checkout.
- No full exact-SHA pytest, full exact-SHA acceptance collection or complete CI was performed. Do NOT report these as PASS.

## Remaining external prerequisites

The signing keys and positive receipts in unit fixtures are **synthetic**. Real kernel event origin, audit capture coverage, sensor private-key isolation, signing-service/observer deployment and read-only broker controls require independent verification in approved OQ-09/A. Owner trust root, off-node backup, OS/CI/Git source measurements and authenticated `AC-N-SEC-05.3` owner inspection remain **NOT_CHECKED**. The unchanged normative suite still has 27 AC and 63 planned synthetic acceptance scenarios; **no runtime AC PASS**.

**D5 = REVIEW_PENDING; P01 = NOT_COMPLETED; P02 = BLOCKED; no merge/deploy.**
