# Eleventh Independent D5 Rework — Developer Handoff

**Target:** P01 D5 test-oracle candidate only. No P01 implementation or runtime AC PASS.

**Rejected HEAD:** `09f2c8d48363a1d1f7ce33ae024d80796ad8fa07`
**Normative Base:** `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`

## ELEVENTH-D5-045 — collector / monitor signer trust boundary

The previous `python -I -S -B` collector inherited root identity. Python import isolation does **not** prevent a root collector reading a root-owned `0600` signer key.

The new D5 contract:

1. **Out-of-band signed role binding:** owner-signed runner policy must contain distinct, non-root `collector_uid`/`collector_gid` and `sut_uid`/`sut_gid`, with privileged `runner_uid=0`. An owner-signed absolute `monitor_key_isolation_probe_path` is also required. These are not appointed by SUT JSON or collector output.
2. **Real negative syscall preflight:** before every acceptance session, root runner independently checks the root-controlled monitor socket and owner-provisioned **synthetic** signing-key guard. A fresh process running as **each** of collector and SUT identities must get actual `EACCES`/`EPERM` for both reading the guard and connecting to the monitor control socket. It verifies real/effective/saved/filesystem identity, zero supplementary groups/capabilities and `NoNewPrivs=1`. A missing socket, guard, isolated role or verifiable denial => `NOT_CHECKED`.
3. **Actual collector privilege drop:** collector subprocess now runs under the signed collector UID/GID with `extra_groups=[]`, restricted environment, isolated Python `-I -S -B`, private non-writable temporary cwd and `NoNewPrivs=1` *before* executing any approved collector bytes. It independently verifies its Linux process credentials/capabilities. It does not receive runner witness key or expected AC values.
4. **No fabricated-event signing:** signed ready/stop monitor receipts remain mandatory and must come from the separately provisioned monitor key. Both collector and SUT are blocked from the monitor control socket in the modeled protected domain. The owner must additionally inspect that the actual private signer key and signing service have the **same or stronger** protection as the tested synthetic guard; that the monitor never signs arbitrary externally supplied event graphs; and that no privileged broker allows the collector to acquire signing capabilities. The D5 code does not install a monitor or prove these external facts.
5. **Read-only measurements:** an unprivileged collector must use an independently approved read-only observation channel. If it cannot see a SUT workspace with `0700`, the test fails closed as `NOT_CHECKED` rather than silently restoring root privileges. OQ-09/A must establish the approved observer's capabilities and OS sandbox.

Regression tests: `tests/test_p01_eleventh_review_regressions.py`. Existing signed-policy and isolated-collector unit fixtures were updated for explicit role binding. All other AC expectations and the frozen 27-AC / 63-scenario JSON remain unchanged.

## Expected independent verification

- Confirm the real collector subprocess UID differs from root and SUT; assert all 4 Linux UID/GID fields, supplementary groups, caps, `NoNewPrivs`.
- Attempt to read a **synthetic** owner-protected monitor signer guard under collector and SUT identities; test a root-only UNIX socket with both identities.
- Test bad/absent signed roles, weak guard permissions, missing monitor/socket and forged monitor receipts, and confirm `NOT_CHECKED`.
- Confirm no signing key, trusted witness key, owner private key or accepted expected-result values reach the collector.
- Verify that the post-run monitor signed evidence still binds run/session/boot/event digest and all 63 acceptance scenarios.

## Gates not claimed

- External post-APR-08 owner approval and trust root; actual monitor signer private key isolation, negative OS test against signer policy, no privileged signing broker; real OQ-09/A collector/read-only measurement channel; kernel/audit graph; Git/CI/OS/off-node collectors; real P01 SUT; owner inspection `AC-N-SEC-05.3`: **NOT_CHECKED**.
- This is D5 candidate improvement, not its independent approval. P01 **NOT_COMPLETED**, P02 **BLOCKED**, no merge/deploy/production.

Local synthetic root-only OS test (separate from the Git checkout): both collector-like and SUT test identities were denied monitor guard and socket access. This does NOT establish that a real signer key was isolated.
