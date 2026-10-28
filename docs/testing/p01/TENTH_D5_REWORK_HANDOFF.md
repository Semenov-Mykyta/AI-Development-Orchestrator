# Tenth Independent D5 rework — Developer handoff

**Scope:** P01 D5 candidate only, no implementation, no runtime acceptance PASS.

**Rejected HEAD:** `f3ae8bc640f01798bb3b573a68bc95c69e3234fa`
**Normative base / protected main:** `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`
**Change scope:** only `tests/` and `docs/testing/p01/`. No normative edits.

## TENTH-D5-043 — independent monitor attestation contract

- `execve_trace` remains mandatory for all 63 automatic acceptance scenarios.
- Owner-signed runner policy now *requires* a separately pinned kernel monitor ID, public-key path and SHA-256, and monitor control socket path. Neither the SUT environment nor a collector's witness HMAC may appoint or impersonate this authority. The external monitor private key is NOT present in this PR.
- Trusted runner validates the root-controlled monitor public key by its owner-signed hash. Before **any** SUT `Popen`, a runner-issued `run_id` and pinned Git SHA / command digest are sent to the root-controlled monitor socket. The independent monitor must respond with an Ed25519-signed pre-launch ready receipt bound to that run.
- Before an AC can PASS, the verifier independently rechecks the ready receipt's signature and timing; verifies a *separate* monitor-signed stop receipt bound to the same run, monitor session, boot ID and hashed event graph; rejects incomplete ancestry, missing children/imports, loss counter, unobserved memory loads, inconsistent event timing and signatures from the collector's own key.
- The collector's ordinary HMAC only authenticates transport of measurements; it is not accepted as proof that a kernel monitor existed.
- No monitor server, kernel hook, owner key or real OS observer is supplied by this candidate. Unavailable monitor => `NOT_CHECKED`; a synthetic unit-test signer/socket demonstrates contract parsing only, NOT kernel provenance or runtime PASS.
- Independent reviewer should attempt to fake positive trace JSON without a live independently keyed monitor. Examine cgroup/namespace coverage, transitive process ancestry and monitor sidecar privilege boundaries as **future OQ-09/A gate**, and report any current false-PASS avenue.

## TENTH-D5-044 — approved SUT read access to pinned script

- Inside `open_pinned_launch`, the runner performs a real `open(O_RDONLY)` preflight in a child process with approved SUT UID/GID and empty supplementary groups against the already FD-pinned Python script.
- Root-owned `0600` unreadable script returns `NOT_CHECKED` before launching the SUT; root-owned `0644` readable script passes this *preflight*.
- A successful read check is NOT an application AC PASS, and the actual OQ-09/A filesystem remains unverified.

## TDD / local isolated checks

- Old candidate: synthetic un-attributed trace accepted by `verify_execution_closure` (reproduced); monitor proof/access helpers were absent.
- New tests: `tests/test_p01_tenth_review_regressions.py`; earlier policy-authorization and trace unit fixtures updated for the stronger contract.
- Local Python 3.13, pytest 9: **112 passed** in unit/regression/integrity suite. `--collect-only` **63 tests**. `compileall` **exit 0**. Acceptance without approved SUT **NOT_CHECKED** (pytest exit 1).
- These are local Developer results and should be independently re-executed on the exact Git SHA. `92+` historical tests do not establish 27 runtime AC PASS.

## Still blocked / not asserted

Independent post-APR-08 owner-approved manifest, owner Ed25519 trust provisioning, owner-signed monitor policy, deployed monitor with kernel/audit trace, protected OQ-09/A runner, actual collector independence, test remote, CI secret-scanning, off-node backup, and authenticated `AC-N-SEC-05.3` owner inspection all remain `NOT_CHECKED`. The owner-controlled installation must preserve separate signing keys and root-controlled OS permissions. **P01 = NOT_COMPLETED**, **P02 = BLOCKED**. No merge, deploy or production action.
