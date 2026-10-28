# Nineteenth D5 Rework — Developer Handoff

Scope: AIO MVP v0.13 P01 D5 test-only verifier and regressions. Frozen normative oracle JSON, seven normative documents, P01 implementation, production Digital Core, protected main, merge and deploy are out of scope.

Previous rejected HEAD: a0064365a4978ed632e1ec36dddd61e3366e53b8
Normative Base: 9d54e4e546753e8f09b8e9d5f4e9d95142f976e8

## NINETEENTH-D5-063 — exact-type execution and witness identity

The previous parser compared the raw witness run object to _run_identity(run) with Python equality, which accepts False == 0, True == 1 and numerically equal integer/float values. The proof/run binding had permissive equality for returncode, run_pid and process_start_ticks.

The verifier now:
1. Admits only exact Python int PID, returncode, start ticks, child PIDs and child return codes in TestRun, rejecting Boolean and float and missing/nonpositive process identities. Run ID and digest fields must be nonempty strings. The process PID/returncode sequences must be tuples.
2. Admits only exact int run_pid, run_returncode and process_start_ticks in IndependentProof plus string-typed authority/identity metadata, before accepting the witness.
3. Compares the JSON run identity parsed from the SHA-pinned raw witness bytes to _run_identity(run) using the already existing recursive, type-strict comparator rather than loose Python equality. The HMAC and SHA checks remain mandatory.
4. Rejects type-confused provenance as ProbeError('NOT_CHECKED: ...') before any normative AC comparison.

The new regression uses HMAC-authenticated SHA-pinned witness files and valid synthetic Ed25519 observer signatures, with separate raw run, proof and runner identity mutations. A valid exactly typed witness still passes unit verification.

## NINETEENTH-D5-064 — non-object top-level witness

The parser checks the type of the decoded root JSON before accessing .get(). Only a JSON object is admissible; arrays, strings, scalar numbers, booleans and null now produce controlled NOT_CHECKED. Root null is tested with a correctly recomputed witness SHA-256 and HMAC.

## Red/green evidence and limitations

- Red locally reconstructed previous verifier (063/064 changes rolled back): 23 failed / 2 passed, exit 1. Some tests exposed an uncontrolled AttributeError.
- Green locally reconstructed source subset: 25 new tests passed; regression suites 12–19: 166 passed / 2 skipped; python -m compileall -q tests exit 0.
- Two skips are acceptance-driver-dependent tests; complete acceptance source is not present in the recovered local subset.
- Exactly locally executed new test source has Git blob SHA e7ba6a4ebab7848456e33706c93e950a400d7d5f. The source patched from the exact previous GitHub probe blob must be verified independently at the new HEAD.
- Full exact-SHA checkout, earlier unit suites, collection of 63 acceptance scenarios, full ast.parse and real P01 runtime tests remain NOT_CHECKED.

The signed synthetic fixtures do not prove real kernel event provenance. Owner trust root, independent signer OS domains, genuine kernel monitor/OQ-09/A, non-root collector, read-only observer, independent OS/Git/CI/off-node measurements, authenticated owner inspection AC-N-SEC-05.3 and all 27 runtime AC remain NOT_CHECKED.

D5 REVIEW_PENDING. P01 NOT_COMPLETED. P02 BLOCKED. No merge/deploy/production.
