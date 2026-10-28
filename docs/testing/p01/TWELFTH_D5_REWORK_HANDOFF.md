# Twelfth Independent D5 Rework — Developer Handoff

**Purpose:** P01 D5 test-oracle candidate, not runtime acceptance, P01 implementation or production deployment.

**Rejected HEAD:** `1d52b69236c1242ecfef7803f95434ca9a0f83ba`
**Normative Base:** `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`
**Scope:** `tests/` and `docs/testing/p01/` only. No normative or protected-main edits.

## TWELFTH-D5-046 — signer deployment identity and full signing interface inventory

The previous synthetic guard blocked two test paths, but did not prove that the *actual* monitor private key or an alternative signing API was inaccessible to SUT/collector. To prevent a fake attestation being accepted solely because a guard had `EACCES`, D5 now **requires live independent OQ-09/A deployment attestation before the first SUT Popen**.

- The existing **owner-signed runner policy** must pin an external OQ inspector ID, Ed25519 public-key path and SHA-256, root-controlled attestation socket, exact approved monitor deployment digest, plus a separate observer deployment digest.
- The independently provisioned inspector is a different authority from the monitor signer and observer (distinct pinned public keys); it must not be the collector or SUT. The inspector receives a fresh runner nonce with run ID, Git SHA, command digest, policy SHA, boot ID and requested sources, and signs a result bound to **this** challenge. Stale/replayed, missing or incorrectly signed receipts => `NOT_CHECKED`.
- Its signed `signer_deployment` evidence must identify the **actual** signer key ID, measured monitor deployment, namespace/MAC and key-storage controls, **all** signing interfaces and their negative access test results for both collector and SUT identities. Every endpoint has an independently attributable OS-probe digest; unknown alternative brokers, unlisted interfaces or signing of fabricated event graphs are disallowed. A fake root-only guard is insufficient.
- This is an explicit **future real inspector/deployment prerequisite**; the PR contains no signer private key, actual monitor or OQ attester. A compromised external inspector is outside this D5 trust model and requires owner provisioning + inspection.

## TWELFTH-D5-047 — positive read-only observer contract

- Owner-signed policy must also pin an independent observer ID, Ed25519 public key+SHA, root-controlled socket with collector-only group access, approved `aio.p01.readonly_snapshot.v1` protocol and covered independent proof sources.
- Independent inspector must attest actual read access for collector identity, actual write-denial under collector **and** SUT identities, unchanged synthetic bytes before/after denied write, complete source coverage, OS probe digest, no SUT-supplied measurements, and **no fallback to root**.
- Each non-kernel measurement returned for any AC now needs a detached Ed25519 observer-signed receipt bound to run ID, Git SHA, command digest, source and exact measurement SHA-256. The existing HMAC cannot substitute for this signature. Kernel `execve_trace` continues to require separate monitor-signed ready/stop receipts.
- Unavailable observer, incomplete source coverage, untrusted/forged snapshot or unavailable independent inspector => `NOT_CHECKED`, not PASS. A future approved read-only broker is necessary to observe SUT `workspace/0700` without granting collector root or SUT identity.

## Local negative tests and evidence limits

`tests/test_p01_twelfth_review_regressions.py`: six synthetic tests, 6 PASS on Linux Python 3.13 / pytest 9 (local pre-publication). Tests exercise signed policy completeness, distinct Ed25519 keys, required signer-interface inventory, fabricated-event refusal, alternative signing brokers, observer source/write-denial gate, challenge replay, forged observer receipt, and collector-only UNIX socket rights. New modules: `tests/p01_oqa_attestation.py` and `tests/test_p01_twelfth_review_regressions.py`.

**NOT independently executed:** complete exact-SHA test suite; full 63 acceptance runtime cases; external signed inspector / broker deployment, real signer actual permission/namespace inspection, true read-only OS/FS/SQLite access, signed kernel evidence, trusted OQ-09/A runner, post-APR-08 owner approval, authenticated `AC-N-SEC-05.3`. No claims of P01 runtime PASS.

**Decision:** Candidate remains `REVIEW_PENDING`; `P01=NOT_COMPLETED`, `P02=BLOCKED`. Do not merge, deploy or touch production.

## Reviewer challenges

1. Try to pass with valid synthetic guard but an accessible alternative signer key/interface. Without the independently attested actual signer deployment and *full* signing-interface inventory, global acceptance must refuse.
2. Attempt to replay a deployment receipt with changed run/nonce, boot, policy SHA, monitor key or approved source list.
3. Try to use collector HMAC or SUT-controlled JSON instead of observer-signed per-source measurements.
4. Verify a *positive* broker read path is independently defined and bound to snapshot SHA, and negative mutation tests deny writes while preserving original bytes. Check collector-only socket mode/identity and absent root fallback.
5. Distinguish D5 contract unit tests from real OQ/owner deployment approval. No real credentials are in this candidate.
