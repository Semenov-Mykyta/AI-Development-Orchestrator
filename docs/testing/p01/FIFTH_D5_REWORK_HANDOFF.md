# P01 D5 — fifth-review rework handoff (sixth independent review candidate)

Status: **CHANGES_REQUIRED → candidate rework, independently NOT APPROVED**.

- Previous rejected SHA: `bf4c491855b0a897c4a5fa46ec82010f477d614c`.
- Immutable normative base `main`: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`.
- PR: https://github.com/Semenov-Mykyta/AI-Development-Orchestrator/pull/1
- Scope: D5 test-oracle quality only, not P01 implementation, merge, deploy or owner acceptance.

## RED → GREEN evidence, tied to fifth reviewer findings

| Finding | Regression / corrective action | Limits |
|---|---|---|
| `FIFTH-D5-028` | `test_fifth_028_reject_any_extra_supplementary_group`: `Groups` must be **empty**; real/effective/saved/filesystem UIDs/GIDs, capabilities and NoNewPrivs still checked against OS `/proc` | Requires independent OQ-09/A runtime identity measurement |
| `FIFTH-D5-029` | `test_fifth_029_reject_changed_external_script_and_ignored_import`: signed policy requires `sut_components_sha256` absolute path/digest map; executable and absolute script argument pinned; ignored executable extensions forbidden | Signed component map must be verified for *complete* import/dependency closure and runtime immutability by an external approved runner; this helper alone cannot prove no late dynamic imports |
| `FIFTH-D5-030` | `test_fifth_030_reject_collector_dependency_from_sut_writable_path`: collector `sys.path` must contain only root-controlled, non-SUT-writable existing locations; existing ownership/digest/import-copy checks remain | True transitive import closure and provenance of external root-installed packages remain part of owner-approved collector deployment (NOT_CHECKED until independently demonstrated) |
| `FIFTH-D5-031` | `test_fifth_031_requires_runner_side_fixture_materialization` and `test_fifth_031_chunk_boundary_preserves_exact_seed_stream`: accepted code now materializes declared protected synthetic files on disk *before* SUT; independently re-reads actual bytes; rejects wrong hash; generator correct across chunk boundaries | 512 MiB file has **not** been materially generated during these unit tests; root-owned pre-existing OS sentinel requires separately provisioned `/synthetic` test namespace, checked before SUT, no production paths touched; off-node copy itself remains NOT_CHECKED |
| `FIFTH-D5-032` | `test_fifth_032_reject_shallow_repository_even_if_reports_match`: scanned reachable commits checked against `git rev-list` and `git fsck --full --strict` on owner-pinned independent mirror, remote ref tips independently fetched with `git ls-remote` from owner-pinned test URL; shallow clones reject | An authenticated external owner-approved remote and complete scanner execution are NOT_CHECKED until OQ-09/A provisioned |

## Test results — developer local, not independent Reviewer evidence

The local code was reconstructed from the previous Git transfer and verified against GitHub Git blob SHAs before rework. On a non-approved local Python 3.13 environment:

```
PYTHONPATH=tests python -m pytest -q \
  tests/test_p01_oracle_integrity.py \
  tests/test_p01_review_regressions.py \
  tests/test_p01_second_review_regressions.py \
  tests/test_p01_third_review_regressions.py \
  tests/test_p01_fourth_review_regressions.py \
  tests/test_p01_fifth_review_regressions.py \
  tests/test_p01_probe_verifier.py
# 63 passed

PYTHONPATH=tests python -m pytest --collect-only -q tests/test_p01_acceptance.py
# 63 collected

PYTHONPATH=tests python -m pytest -q -x tests/test_p01_acceptance.py
# NOT_CHECKED, fails intentionally without genuine approved SUT/runner

python -m compileall -q tests
# exit 0
```

Older smoke verifier now patches the temporary collector *authorization seam in that unit test alone*: an unsigned temporary local file cannot satisfy the actual root-owned signed policy. These tests do not imply working P01 acceptance.

## Security / explicit non-claims

- Do not use real credentials, production Digital Core or live GitHub writes as synthetic probe targets.
- No normative files changed; no P01 implementation. All 27 runtime AC `NOT_CHECKED`; P01 NOT_COMPLETED, P02 BLOCKED.
- Provisioning, owner-authenticated signed trust root, effective/saved UID/GID, full dynamic component and import closure, CI/OS/Git scanner output, real 512 MiB/off-node backup, sandbox isolation and owner `AC-N-SEC-05.3` are separately NOT_CHECKED.
- `git_test_remote_url`, `git_scan_mirror_path`, `sut_components_sha256` and `/synthetic` synthetic root are signed policy claims; mere presence of fields is **not** external owner authentication. A test runner must reject unprovisioned/stale/unsafe trust evidence.
- Reviewer: test false PASS via malicious `sys.modules` imports, script flags, shallow/incomplete commit graphs, symlink/import TOCTOU, injected ignored files, and insufficient metadata provenance. If any can pass, return CHANGES_REQUIRED.
