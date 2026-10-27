# AIO P01 independent test oracle — D5 candidate (not approved)

Only test expectations and acceptance harness, no implementation code. All 27 P01 AC initially `NOT_CHECKED`.

**Commands for local static oracle validation** (not runtime P01 PASS):

```sh
python -m pytest -q tests/test_p01_oracle_integrity.py
```

**Red tests before implementation** (a failure with `NOT_CHECKED` is expected):

```sh
python -m pytest -q -x tests/test_p01_acceptance.py
```

Future implementation PR must supply an approved *test-only* module through `AIO_P01_SUT_OBSERVER` with `observe(ac_id,{"scenario_id": ..., "synthetic_input": ...}) -> dict`; it is a harness bridge, not a runtime API requirement. Tests must run on approved Ubuntu 24.04/Python 3.12 isolated sandbox and capture independent real OS/CI evidence; mock output never suffices for the mandatory security tests. This is not a substitute for independent D5 review of expected values. See `REVIEW_HANDOFF.md`.
