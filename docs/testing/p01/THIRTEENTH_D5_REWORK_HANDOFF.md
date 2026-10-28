# Thirteenth Independent D5 Rework — Developer Handoff

**Scope:** only P01 D5 test-oracle harness / tests. No P01 implementation, OQ-09/A deployment, normative-file changes, merge, or runtime acceptance PASS.

- Previous reviewed HEAD: `d3583cb13129ff979abfa5942d5ae44693061656`
- Normative base: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`
- Findings: `THIRTEENTH-D5-048` HIGH; `THIRTEENTH-D5-049` MEDIUM.

## 048 — Multi-source signed observer receipt merge

On exact previous HEAD, `_parse_witness()` already returned a copy of each measurement without the per-source `readonly_observer_receipt` metadata. An assertion that it necessarily merges this metadata is therefore not supported by that code. Rather than silently changing the frozen oracle contract, add a positive end-to-end *unit verifier* regression that generates **two distinct valid Ed25519-signed receipts** for `sqlite_snapshot` and `subprocess_audit`, verifies them independently, writes two separate HMAC-protected witness files, then calls the real `verify_independent_proofs()` with the corresponding TestRun. Only the normative observation fields merge, with no spurious `readonly_observer_receipt` key; source-specific receipts remain on the two IndependentProofs. A second case checks that altered observations fail signature/digest checks **before** any merge.

No change to `P01_ORACLES.json`, no expected values weakened, no acceptance PASS asserted.

## 049 — Primary OS syscall witness bytes / provenance contract

`verify_oqa_receipt()` no longer treats any length-64 string as proof of OS observation. The independently signed attester receipt must include `os_probe_artifact.os_probe_bytes_b64` with bounded, strict-base64, canonical JSON bytes for **every** monitor-signing interface and the read-only observer. The verifier:

1. Recomputes SHA-256 of the actual primary witness bytes and matches the owner-attested digest, requiring lowercase hex.
2. Binds the witness to challenge nonce, run ID, Git SHA, command SHA, policy SHA, attester ID, boot ID, exact deployment SHA and target endpoint.
3. Binds all four OS role fields (SUT/collector UID+GID) and validates syscall identities, target, namespace, MAC profile, monotonic timestamps, and exact expected operation/errno coverage.
4. Rejects missing, duplicate, unexpected or mismatched syscall events, corrupted/noncanonical/missing bytes, changed deployment or source identity, and untested duplicate signing endpoints.
5. Requires both observer positive `rpc_read=ALLOW` and negative collector/SUT `rpc_write=EACCES/EPERM` artifacts, as well as a well-formed unchanged write-denial file SHA.

The attester remains a separately owner-pinned Ed25519 authority; its receipt signature binds the primary byte artifacts. **A signature and verified digest cannot by themselves prove a syscall happened**: real attester deployment, kernel/OS provenance and owner verification remain external OQ-09/A `NOT_CHECKED`. Synthetic fixtures purposely demonstrate format and mutation rejection only.

## Local test evidence and limitations

- Locally recovered test-only harness: `25 passed` across `test_p01_twelfth_review_regressions.py` and `test_p01_thirteenth_review_regressions.py`; `compileall` exit 0.
- Relevant Git blob SHA on the locally tested files:
  - `tests/p01_oqa_attestation.py`: `89c5581929adf646d193b3f28cf2cbcf56bcbc76`
  - `tests/test_p01_twelfth_review_regressions.py`: `71de53479bacd5f600a2a714e166357a71039036`
  - `tests/test_p01_thirteenth_review_regressions.py`: `8199640f382a4072e25a837ce5f18a5aee27cc70`
- The local verifier used in the positive multi-source regression was restored from an older project source and patched to match the **already-present observer metadata filtering** on the previous GitHub HEAD. This is not an exact-SHA full checkout. The Reviewer must run all tests independently on the resulting GitHub HEAD.
- All 63 acceptance cases, full regression suite, approved owner trust root, monitor, attester, observer, independent real OS/CI/Git measurements, and runtime P01 remain **NOT_CHECKED**. Do not equate test discovery, synthetic signatures or local unit PASS with runtime AC results.

## Review instructions

Confirm exact GitHub HEAD and unchanged normative Base; independently inspect prior `_parse_witness()` and acceptance order (`verify_readonly_observer_measurements` before `verify_independent_proofs`). Execute positive two-receipt test and all primary-artifact negative mutations. Inspect trust boundaries for another false PASS or false NOT_CHECKED, including compromised attester or forged OS evidence.

**D5 = REVIEW_PENDING; P01 = NOT_COMPLETED; P02 = BLOCKED; no merge/deploy.**
