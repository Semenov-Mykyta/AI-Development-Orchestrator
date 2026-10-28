# Seventeenth Independent D5 Rework — Developer Handoff

**Scope:** only P01 D5 tests/harness. No normative docs, frozen `P01_ORACLES.json`, implementation P01, production Digital Core, merge or deploy.

**Previous rejected SHA:** `adeaf3d4a88900889f6dab8f7c3d9b71d9e4ced5`
**Normative Base:** `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`

## SEVENTEENTH-D5-059 — distinct PEM digests can carry one key

Preserve existing owner-signed PEM-file SHA-256 checks; those establish **serialized file integrity**, not Ed25519 **public-key identity**. In `tests/p01_oqa_attestation.py`, after independently loading and pinning attester, observer, monitor and kernel-audit PEM files from root-controlled paths, `require_live_oqa_attestation()` now calls `require_distinct_oqa_signing_keys()`. The helper compares each loaded Ed25519 public key in canonical `Encoding.Raw / PublicFormat.Raw` form and fails closed unless there are exactly four distinct key identities.

Positive regression: four actual distinct root-controlled test keys pass this admission gate. Negative regression: four valid PEM renderings (LF, extra LF, CRLF, double LF) of **the same Ed25519 public key**, with four different correct PEM SHA-256 hashes, produce `NOT_CHECKED` before an attester RPC. No private production key or actual monitor is used.

**Boundary:** key-byte uniqueness is required but not sufficient for OS signing-key isolation; independent OQ-09/A verification remains `NOT_CHECKED`.

## SEVENTEENTH-D5-060 — normative JSON type confusion

`tests/p01_probe.py` now uses `_normative_json_value_equal(expected,actual)` in the normative AC comparator. It requires **exact Python/JSON types recursively** in scalars, dicts and lists. For example, expected `clone_calls: 0` rejects measured `False`; expected `admission_continues: true` rejects measured `1`. Equal numeric values of different JSON types (integer vs float) also reject in ordinary AC equality. The explicit `at_most` numeric quota operator still accepts actual int or float within the limit, but **never bool**.

The regression also constructs independent HMAC-protected, SHA-pinned witness files with correct run/Git/command/collector identity, proving that a correctly authenticated witness with an incorrect JSON value type still produces `FAIL` rather than a false PASS.

Existing `verify_independent_proofs(..., evaluate_expected=False)` and execution-closure-before-normative-comparison order are unchanged.

## Regression results and limits

- Red-first on the previous local source: **12 failed, 17 passed**. The 059 attack passed digest-only admission and reached the missing observer socket, while 060 type confusions passed normative comparison.
- Green on the locally recovered, **not full exact-SHA** test subset: **33 passed** in `tests/test_p01_seventeenth_review_regressions.py`; across regression suites 12–17: **114 passed, 2 skipped**; local `python -m compileall -q tests` exit 0.
- Two skips concern acceptance-source tests absent from the local recovered subset; complete exact-SHA checkout, regression suite, 63 acceptance collection and real runtime AC remain **NOT_CHECKED**. These results must be independently verified on the new GitHub HEAD.
- Local edited attestation Git blob: `e9707351901dd240b6b85913c1a04bffadb68a2c`.
- Published direct-GitHub probe changes are deliberately limited to the same normative equality helper/branch used in local tests; the local historical probe file is **not** a complete exact-SHA copy. Do not infer full acceptance results from local tests.
- New regression Git blob: `17069c492b473f48f01d8e4df3db6c6c28539bec`.

## External gates

Owner trust root / policy authority, OS isolation of all four private keys, actual OQ-09/A attester and kernel audit, signed read-only observer, complete process/OS/Git/CI/off-node measurements and authenticated user owner review `AC-N-SEC-05.3` remain NOT_CHECKED. Synthetic Ed25519 signatures are not actual kernel evidence.

**D5 = REVIEW_PENDING; P01 = NOT_COMPLETED; P02 = BLOCKED; no merge/deploy.**
