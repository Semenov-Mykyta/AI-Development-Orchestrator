# P01 D5 — Second Independent Review Remediation (NEW-D5-010…017)

**Candidate for third independent review. NOT_APPROVED.** All 27 P01 AC are still **NOT_CHECKED**. This is test-only software, not implementation of AIO runtime. No merge, deploy, production permissions or owner inspection are authorized.

- Normative baseline: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8` (APR-08 v0.13; independently authenticated post-APR-08 owner manifest still NOT_CHECKED).
- Second review rejected SHA: `659255f5a6ac1c0c8151cd3814c9f5ab528323b5`.
- Scope: original branch `feature/REQ-N-12-p01-d5-oracles`, PR #1. No edits to any normative documentation; no P01 application runtime added.

## Defect-by-defect change / exact red-green tests

**Before fixes:** `python -m pytest -q tests/test_p01_second_review_regressions.py` produced **11 FAIL**, reproducing all eight findings (D5-013 has 3 parameterized errors).

| Finding | Action in candidate | Independent verification / limitation |
|---|---|---|
| NEW-D5-010 | Remove fictional journal enum `FAIL_CLOSED` from the `before_intent` case. Assert `system_mode == FAIL_CLOSED`, `journal_record_created == false`, `remote_write_calls == 0`. | `test_new_d5_010_*`; run OS / journal probes later. No normative enum change. |
| NEW-D5-011 | `log-quota-overflow` asserts **measured** `owned_log_bytes_after <= 128 MiB` (not merely protected-record integrity), plus `log_quota_enforced`. Adds expired log bound. | `test_new_d5_011_*`. No prescribed eviction algorithm: inequality instead of forcing exactly 128 MiB. Real FS test NOT_CHECKED. |
| NEW-D5-012 | Post-remote fault asserts exactly one independently witnessed remote write before restart and exactly one total after restart, durable intent, `UNCERTAIN`, zero duplicates/ACK. | `test_new_d5_012_*`. Must use test-only controlled FS and instrumented remote; none built/claimed. |
| NEW-D5-013 | Require actual captured `errno` (e.g. `EACCES` vs `ENOENT`), attempted syscall and exact synthetic path/endpoint. | 3 parameterized `test_new_d5_013_*`; OS denial still NOT_CHECKED. |
| NEW-D5-014 | Every credential `DENY` asserts independent `outbound_calls == 0`; each scenario includes outbound counter source. | `test_new_d5_014_*`; no real integration/credential touches. |
| NEW-D5-015 | Replace unreachable `verify_independent_proofs(case, {}, {}, run)` with pinned external collector seam plus witnessed capture verification. One **actual dummy subprocess + separately-reading test collector** smoke test proves both positive and negative code paths. | `test_real_subprocess_and_external_fs_collector_positive_and_negative`; this is plumbing **unit** PASS, **not** P01 SUT/OS/CI PASS. External production-grade test collectors remain NOT_CHECKED. |
| NEW-D5-016 | Bind signed witness JSON to runner-issued run ID, exact Git HEAD SHA, command digest, fixture digest, observed child PID/start ticks, observed exit status/sequence and approved collector digest. Read measured values from authenticated witness file itself; reject mismatched fields, replay, wrong SHA/command, tampering. SUT stdout and `expected_observations` are never inputs to collector. | `test_p01_probe_verifier.py` (including negative cases). Pinning is not an independent attestation that the collector/runner is honestly implemented. Approval and trusted OS/CI/Git collectors remain separate gates. |
| NEW-D5-017 | Idempotency fixture provides two explicit identical registration steps. Acceptance actually invokes the SUT twice in the **same** workspace (rather than trusting `prior_submission_count`), requires `registration_command_executions == 2` measured by external process audit, and `project_count == 1` from SQLite snapshot. | `test_new_d5_017_*`. Real SUT replay acceptance remains NOT_CHECKED. |

## Executed commands (local preparation environment only)

- `python -m pytest -q tests/test_p01_second_review_regressions.py tests/test_p01_probe_verifier.py tests/test_p01_review_regressions.py tests/test_p01_oracle_integrity.py` → **38 PASS**.
- `python -m pytest --collect-only -q tests/test_p01_acceptance.py` → **63 collected**.
- `python -m pytest -q -x tests/test_p01_acceptance.py` → **exit 1 / ERROR NOT_CHECKED** (requires approved real SUT, approved exact SHA, collector code digest and runner-only witness key).
- `python -m compileall -q tests` → **exit 0**.
- Environment: **Debian 13 / Python 3.13.5 / pytest 9.0.2**. **Not** the owner-approved OQ-09/A Ubuntu 24.04 / Python 3.12 runner; therefore environment gate NOT_CHECKED.

## Mandatory review / separation of authority

1. Validate exact HEAD in PR #1; compare all synthetic expectations to approved SPEC v0.13 independent of Developer assertions and frozen digest.
2. Independently run tests against exact checkout; verify no false acceptance using `expected_observations` echo, malformed witness bytes, replay, incorrect exit code, misbound SHA or collector.
3. Inspect pinned collector integration: `AIO_P01_APPROVED_COLLECTOR`, `AIO_P01_APPROVED_COLLECTOR_SHA256`, `AIO_P01_TRUSTED_WITNESS_KEY_PATH`, `AIO_P01_APPROVED_SUT_SHA`, `AIO_P01_SUT_REPO`. Authenticated trust-anchor approval and OS isolation of witness key/collector must be verified **outside** SUT, not assumed by env naming.
4. A dummy test plugin that infers expected outcomes is **never** independent evidence. Review genuine collector logic and actual test OS/CI/Git instrumentation before P01 acceptance. Real scanners, repo-history enumeration, negative pre-commit/CI runs, OS syscall denial, test FS failure, offnode backup and credentials inventory inspection remain **NOT_CHECKED**.
5. D5 approval cannot be interpreted as technical PASS of P01 AC or owner `AC-N-SEC-05.3` PASS. This PR is authored by owner identity and cannot act as §4.6 bootstrap owner PR.

**Pending external gates:** independently approved post-APR-08 manifest, independent D5 review, isolated approved runner, genuinely trusted collectors, full security scans/CI, actual owner inspection on separate PR identity. `P01=NOT_COMPLETED`, `P02=BLOCKED`.
