# P01 D5 — seventh-review rework handoff (candidate only)

- Previous Independent Reviewer verdict: **CHANGES_REQUIRED** on `449f5f992448f3876635b7e02c663552b42dcaca`.
- Frozen normative base (unchanged): `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`.
- Target findings: `SEVENTH-D5-037`, `SEVENTH-D5-038`. **No changes to normative specs or implementation of P01.**

## Reproduction-first fixes

1. `SEVENTH-D5-037`: pinned `/usr/bin/env` with `argv=['/usr/bin/env','python3','payload.py']` previously accepted an unsigned script outside the frozen checkout. Test reproduces it with clean HEAD, then requires `ProbeError`. Direct approved executable still allowed. Known executable wrappers (including resolved symlinks) now denied; extending approved command modes requires independently attested execution chain. Signed policy and full component closure remain mandatory.
2. `SEVENTH-D5-038`: synthetic `workspace/evidence/` previously remained runner-owned and evidence file mode `0600`, making an erroneous SUT eviction attempt indistinguishable from retention compliance because both read and unlink were blocked by OS. Fixture handoff now takes independently approved `sut_uid/sut_gid`, verifies bytes before `chown`, assigns only generated SUT evidence files/directories, and explicitly proves read and lawful deletion capability in a separate non-privileged synthetic subprocess. Runner-owned collector/key/witness remain outside workspace and separate from this handoff. Reproduction test checks former root-owned evidence cannot satisfy the new access prerequisite.

## Local results (NOT P01 acceptance)

- Reproduction-first: two targeted tests fail on prior checkout; passed after the code fixes.
- `python -m pytest -q` with the nine selected unit/regression/integrity test files (including `test_p01_seventh_review_regressions.py`): **76 passed**, exit `0`, local Linux/Python 3.13 environment, not approved OQ-09/A.
- `python -m pytest --collect-only -q tests/test_p01_acceptance.py`: **63 collected**, exit `0`.
- `python -m pytest -q -x tests/test_p01_acceptance.py` without approved SUT/runner: `NOT_CHECKED`, exit `1`, fail closed at fixture setup.
- `python -m compileall -q tests`: exit `0`.

## Reviewer focus

- Verify both negative cases independently, including `env` symlink/wrapper variants and a bad retention implementation actually capable of deleting synthetic evidence.
- Verify the new runner-side OS access probe and no trust leakage to SUT workspace, and check no root-owned protected SUT fixture yields a spurious PASS.
- Verify all 27 AC/methods/63 scenarios, exact immutable base, no false PASS in independent collectors.
- Validate the exact remote HEAD on PR #1 before verdict. These local checks do **not** establish real collector provenance, OQ-09/A isolation, owner trust root/manifest, CI/OS/Git negative proofs or runtime AC PASS. `P01 = NOT_COMPLETED`; `P02 = BLOCKED`; no merge/deploy.

## PR head synchronization check

Independent Reviewer must verify **both** the live branch ref and PR #1 API head SHA are identical before reviewing the PR. If the PR diff/metadata is stale, verdict is `BLOCKED` until synchronized; a matching feature ref alone does not authenticate the PR snapshot.
