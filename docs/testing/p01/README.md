# AIO P01 D5 test-oracle candidate — rework after CHANGES_REQUIRED

**Not approved. NOT_CHECKED for every runtime AC. No P01 implementation code.**

This folder records original evidence and a later correction under `D5_REWORK_HANDOFF.md`. Earlier `DEVELOPER_REPORT.md` and `PREFLIGHT_REPORT.md` document the first candidate and must **not** be treated as the current outcome; original `observe()` test-bridge recommendations are superseded.

## Offline oracle-package checks only (not P01 acceptance)

```sh
python -m pytest -q tests/test_p01_oracle_integrity.py tests/test_p01_review_regressions.py tests/test_p01_probe_verifier.py
python -m pytest --collect-only -q tests/test_p01_acceptance.py
```

The acceptance suite is deliberately **not runnable to PASS** without a real P01 SUT and reviewed independent OS/CI/Git/FS test-runner collectors. In the current state it must stop as `NOT_CHECKED`:

```sh
python -m pytest -q -x tests/test_p01_acceptance.py
```

`AIO_P01_SUT_OBSERVER` is **removed**. There is no runtime `observe()` interface to implement. The test-only launch setting `AIO_P01_SUT_COMMAND` is not an endorsed SUT API or valid acceptance evidence by itself; the runner must execute the SUT in the approved OQ-09/A isolation profile, with **no inherited production credentials**, and independently collect all required measurements. The current evidence verifier refuses untrusted/missing witnesses. Do not fake witness records or claim OS denial from a Python bool.

Approved source is immutable SPEC v0.13 at base `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`, not this README. New SHA must be independently reviewed on PR #1, after which other P01 gates still apply. No merge/deploy permission.
