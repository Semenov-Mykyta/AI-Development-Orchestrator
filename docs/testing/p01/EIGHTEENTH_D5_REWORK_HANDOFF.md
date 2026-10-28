# Eighteenth D5 Rework — Developer Handoff

Scope: P01 D5 tests and test harness only; normative Base, frozen P01_ORACLES.json, production Digital Core, P01 implementation, merge and deploy are out of scope.

Previous rejected SHA: 573c4a419ced0156304e7210de3ef3c1b2a4d8b4
Normative Base: 9d54e4e546753e8f09b8e9d5f4e9d95142f976e8

## EIGHTEENTH-D5-061 — signed capture / raw witness type mismatch

The original normative recursive JSON comparator now also guards two earlier independent-evidence trust boundaries: the capture parsed from the SHA-pinned raw witness must be exactly equal in JSON type and value to observer-signed proof.captures; conflicting same-name measurements from two independent sources must fail closed as NOT_CHECKED. Nested arrays and objects also require exact types. Per-source readonly_observer_receipt metadata remains separately authenticated and excluded from normative source merge.

The new regression uses actual Ed25519-signed synthetic observer receipts, SHA-pinned raw independent-witness files, HMAC-authenticated proof metadata, run/Git/command/collector identity checks, and conflicting 0/false, 1/true, float/integer, nested JSON values. A two-source positive case with matching bool values and different signed receipts still succeeds.

## EIGHTEENTH-D5-062 — nonfinite quota and JSON evidence

Normative at_most measurements now reject NaN, Infinity and -Infinity using explicit finite-float checks; signed measurements must be int or float, never bool, and must be nonnegative and within the declared quota. Canonical JSON serialization explicitly disallows NaN/Infinity; raw witness JSON parsing explicitly rejects Python nonstandard NaN/Infinity tokens and maps invalid evidence to NOT_CHECKED. Ordinary recursive numeric equality additionally rejects nonfinite float values. Positive tests preserve valid finite 0, 100.5 and 128 MiB boundary cases.

## Local test evidence and limits

Exactly the new published regression source, test_p01_eighteenth_review_regressions.py, produced 15 FAIL / 12 PASS on the previous reconstructed local probe and 27 PASS on the fixed reconstructed local probe. Last-seven-round available local regression suites: 141 PASS / 2 SKIP; local compileall exit 0. Two SKIPs require a full acceptance test file not present in the reconstructed local subset.

The regression source Git blob is 3a4a25ab42574680a9275c3bdd62b53defb4c586 and matches the local executed file. The published p01_probe.py is patched from the exact previous GitHub blob, rather than the locally incomplete probe copy.

Full exact-SHA pytest, full acceptance collection of 63 candidate scenarios, approved trust roots, genuine independent kernel/OS/CI/Git/offnode evidence, four isolated private signing-key domains, OQ-09/A, authenticated owner inspection AC-N-SEC-05.3, all P01 runtime AC: NOT_CHECKED. The independently signed test receipts are synthetic and do not assert real kernel provenance.

D5 REVIEW_PENDING; P01 NOT_COMPLETED; P02 BLOCKED. No merge/deploy.
