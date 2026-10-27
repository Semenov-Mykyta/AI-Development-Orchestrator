# P01 D5 — Sixth Review Rework Handoff (for seventh independent review)

**Status: candidate / not approved. No runtime P01 AC is claimed PASS.**

Normative base: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`  
Previous independently reviewed HEAD: `2e69391ed1c4cdb6ba6fb0a33a12d08064bb5857`  
PR #1: https://github.com/Semenov-Mykyta/AI-Development-Orchestrator/pull/1

## Reviewer findings and correction

| Finding | Red reproduction against preceding HEAD | Candidate correction |
|---|---|---|
| SIXTH-D5-033 (HIGH) | `policy` was local to session fixture and not in acceptance test scope | Signed `git_test_remote_url` is returned from the session fixture; `build_p01_test_run()` receives this URL and creates `TestRun`. A synthetic unit test checks this data path; it is **not** proof of approved SUT execution. |
| SIXTH-D5-034 (HIGH) | `python -B payload.py` with an unsigned relative script was previously accepted | Interpreter entry-point is conservatively restricted to a directly supplied absolute, existing script included in signed component manifest. An interpreter flag in that position (including `-B`, `-m`, `-c`) fails closed. Listed components remain byte-pinned. |
| SIXTH-D5-035 (HIGH) | Cached attacker module in parent `sys.modules` could influence imported collector dependency | `collect_trusted_evidence()` calls a byte-pinned loader that executes collector in a **new process** using Python `-I -S -B`, with clean environment and controlled import path. Parent `sys.modules` is not inherited. Signed collector bytes are passed directly to this isolated subprocess; unavailable third-party imports fail closed. Added positive stdlib-only and negative cached-dependency regressions. |
| SIXTH-D5-036 (MEDIUM) | First synthetic file remained after later file failed; partial data could persist after OS fault | `materialize_synthetic_objects()` rolls back **all newly created files** on write, fsync, post-write SHA/size recheck or subsequent fixture failure; `O_EXCL|O_NOFOLLOW` avoids overwriting or following symlinks. Regressions test SHA mismatch, later-file failure, post-write verification and fsync error. |

## Local isolated checks (not independently reviewed yet)

- Integrity tests, prior regression sets, probe verifier and sixth-review regression: **71 passed** (local container, Python 3.13).
- `python -m pytest --collect-only -q tests/test_p01_acceptance.py`: **63 collected**.
- `python -m pytest -q -x tests/test_p01_acceptance.py`: **exit 1**, expected `NOT_CHECKED: SUT SHA and runner not approved`.
- `python -m compileall -q tests`: **exit 0**.
- On the preceding exact SHA, new tests reproduced missing helper/collector isolation, the interpreter-flag bypass, and incomplete fixture rollback (5 FAIL in initial red run). This is local developer evidence, not an independent Reviewer verdict.

## Residual gates and trust boundaries

A new collector subprocess prevents inheritance of the parent's module cache but does **not** by itself demonstrate OS permissions, trusted owner root provisioning, real test runner isolation or true independence of all OS/CI/Git measurements. Non-stdlib imports unresolved in the isolated interpreter fail closed until trusted collector dependencies and runtime are separately approved. The executed SUT and owner-signed policy are not provided by this PR.

All seven approved normative documents remain unchanged; no product code or P02–P07 work; no merge or deployment; no actual secrets. `D5=REVIEW_PENDING`; `P01=NOT_COMPLETED`; `P02=BLOCKED`.

**Reviewer recheck:** Try cached-module poisoning in parent `sys.modules`, Python flags such as `-B`, test run metadata scope, partial filesystem writes and post-write SHA fault; independently check exact Git SHA/diff, test execution, and all P01 AC/methods. Do not approve runtime AC or owner inspection based on this package.
