# Sixteenth Independent D5 Rework — Developer Handoff

**Scope:** P01 D5 test-only harness and regression tests; unchanged normative Base, frozen P01_ORACLES.json and production. No P01 implementation or runtime acceptance.

Reviewed/rejected HEAD: `807f633d450d3471d584f81e496072e81e7da79f`
Normative Base SHA: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`

## SIXTEENTH-D5-057 — strict signing-broker counter

The attester-signed `signer_deployment.unaudited_signing_brokers` field must have exact Python type `int` and exact value `0`. Reject `False`, `0.0`, `True`, `-1`, `1`, null, a string, list, dict and an absent field with `OQAttestationError('NOT_CHECKED: ...')`, not an assumed zero. A positive synthetic test still accepts integer 0.

## SIXTEENTH-D5-058 — endpoint type admission before hashing

Validate every `signer_deployment.signing_interfaces` member as a dict with a nonempty *string* `target` **before** set uniqueness checks. Validate the separately signed `kernel_audit.receipt.discovered_signing_endpoints` as a list of nonempty strings before `set()` and sorting. Malformed/unhashable targets (list, dict, null, int), non-object interfaces, empty and repeated endpoints now raise controlled `OQAttestationError('NOT_CHECKED: ...')` instead of raw Python `TypeError`.

## Regression evidence

`tests/test_p01_sixteenth_review_regressions.py`: 30 parametrized test cases. Uses actual `verify_oqa_receipt()` and freshly signed **synthetic** Ed25519 attester + kernel-audit envelopes. Red-first run on previous source: 6 failures, including two silently accepted numeric-type bypasses and four unhandled TypeErrors. Post-fix: 30 PASS. Local restored D5 subset across regression suites 12–16: **81 PASS, 2 SKIP**. `python -m compileall -q tests` exit 0 in that subset.

**Important limits:** The two skips require `tests/test_p01_acceptance.py`, which is absent from the locally reconstructed subset. A **full exact-SHA Git checkout and complete pytest / acceptance collection have not been executed**, and no GitHub CI status is claimed. The Reviewer must run the full exact-SHA suite; do not label this local subset a complete project PASS.

## Git blobs from the locally tested files

- `tests/p01_oqa_attestation.py`: `4a2afba7528a91b58730e603470af5090173b0d4`
- `tests/test_p01_sixteenth_review_regressions.py`: `42415611c0768a05ce9b56fef5a78417501cb224`

The test-only JSON, owner-signed policy, kernel/observer receipts and OS events are synthetic; their signatures do not prove real kernel provenance or OQ-09/A readiness. Owner trust, attester/sensor deployment and private-key isolation, independent source measurement, actual process closure and authenticated owner inspection remain NOT_CHECKED.

**D5 REVIEW_PENDING; P01 NOT_COMPLETED; P02 BLOCKED; no merge/deploy.**
