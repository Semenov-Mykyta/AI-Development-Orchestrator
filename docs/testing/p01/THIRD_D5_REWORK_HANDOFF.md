# P01 D5 — Third Reviewer CHANGES_REQUIRED / rework handoff

**Status:** PRE-REVIEW; **all 27 runtime P01 AC remain NOT_CHECKED**. This adds *test-oracle and runner contract* controls only; it does not implement AIO P01, deploy any collector, or approve a trust root.

**Normative base:** `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8` (APR-08 v0.13). **Prior rejected HEAD:** `8e622da7982b59e78c1aa4605febbd4b6e9f9317`. Target PR #1, branch `feature/REQ-N-12-p01-d5-oracles`.

## Independent third review defects addressed

| Finding | Red reproduction / revised measurable constraint |
|---|---|
| THIRD-D5-018 | Two blocked quota cases explicitly forbid deletion, compare protected evidence digests before and after, and require no offnode backup; allowed eviction requires independently witnessed backup SHA, real receipt and `backup_verified_event_seq < eviction_event_seq`. |
| THIRD-D5-019 | Runner no longer accepts its collector key/path/digest as self-authorizing environment variables. A dedicated **out-of-band owner-pinned Ed25519 public key** verifies a signed collector-policy document, binding SUT Git SHA, repo, command digest, UID/GID, runner UID, collector path+SHA256 and witness-key path. The three fixed trust files are rooted under `/etc/aio-orchestrator/trust/`, with root-owned non-writable ancestry. A self-signed forged collector fails signature check. The actual owner's out-of-band key provisioning/approval is **NOT_CHECKED**. |
| THIRD-D5-020 | Runner requires a **real denied OS syscall**, under the intended SUT UID/GID, against a synthetic witness-key file. If the same UID is used, file is accessible, OS isolation is unavailable, or signed runner policy is missing, **NOT_CHECKED**. Actual SUT subprocess must run under the signed distinct UID/GID (Linux `Popen(user=..., group=...)`) and OS `/proc/<pid>/status` identity is inspected while it lives. In local synthetic test, a separate UID gets EACCES. This is not evidence of deployed production isolation. |
| THIRD-D5-021 | Pre/post/while reconciliation captured independently. Exact ordered trace: `UNCERTAIN → RECONCILING → CONFIRMED`, one remote reconciliation query, confirmed applied outcome, one write total, zero writes during `UNCERTAIN`; a static field containing a plan is not sufficient. Enum remains the normative SPEC §8.1. |
| THIRD-D5-022 | Scanner must independently enumerate **current test-remote heads and exact SHA**, separately record scanned-ref SHA map, and compare dynamic key/value sets. An additional unscanned fourth branch fails closed; unavailable refs remain NOT_CHECKED. The fixture's original static three refs cannot stand in for enumeration. |
| THIRD-013 follow-on | Filesystem denial requires **pre-existing synthetic sentinel** with independently checked digest unchanged before/after; network denial must target a **listening synthetic test endpoint** under explicit OS network denial rather than conflating missing routing or nonexistent target with policy denial. |

## Reproducible red/green (local preparation only)

**Before fixes** on original third-review HEAD oracle logic, `tests/test_p01_third_review_regressions.py` had **10 FAIL** (ten reproduced defects/variants). After fixes:

```sh
python -m pytest -q tests/test_p01_third_review_regressions.py tests/test_p01_second_review_regressions.py tests/test_p01_probe_verifier.py tests/test_p01_review_regressions.py tests/test_p01_oracle_integrity.py
# 50 PASS, exit 0 (local Debian/Python 3.13.5; NOT approved OQ-09/A runner)
python -m pytest --collect-only -q tests/test_p01_acceptance.py
# 63 collected, exit 0
python -m pytest -q -x tests/test_p01_acceptance.py
# NOT_CHECKED (no signed owner trust root or real SUT); exit 1
python -m compileall -q tests
# exit 0
```

## External trust anchor and mandatory limits

A **test operator outside AIO agents** must separately approve/install the owner Ed25519 root and signed manifest. The trust directory `OWNER_PUBLIC_KEY_PATH`, `OWNER_SIGNED_POLICY_PATH`, `OWNER_POLICY_SIGNATURE_PATH` is a fixed runner path, not selected by SUT configuration. Required signed JSON schema: `aio.p01.owner_signed_collector_policy.v1` with `collector_path`, `collector_sha256`, `witness_key_path`, `sut_uid`, `sut_gid`, `runner_uid`, `sut_command_sha256`, `sut_repo_path`, `git_sha`, `authorized_by`, and `scope=P01-D5`. No private key or real credential is stored in repository. The Ed25519 verification dependency must be pinned and hashed in the independently approved OQ-09/A test environment before actual acceptance.

A signed manifest verifies that collector bytes were authorized **only if** the owner's root key was independently authenticated and provisioned outside the SUT trust domain. Signing a fake policy with a fake key does not prove approval. A test-only unit fixture that controls a test keypair does **not** demonstrate external owner authorization. Validating a synthetic test UID syscall does **not** demonstrate the production Digital Core boundary. The separate trusted collectors for Git refs, CI, FS, OS and off-node remain unimplemented/NOT_CHECKED, and PR #1 remains owner-authored; it cannot satisfy `AC-N-SEC-05.3`.

**No fake PASS**; P01 `NOT_COMPLETED`; P02 `BLOCKED`. D5 candidate cannot be frozen until independent reviewer verifies new SHA and owner-approved manifest provenance independently is handled.
