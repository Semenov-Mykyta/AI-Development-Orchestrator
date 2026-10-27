"""D5 executable AC checks: fail closed until real isolated SUT adapter is provided.

The adapter is *only* a test observation bridge, not a normative runtime interface.
Each observation must be grounded in real isolated test execution. For OS/CI/remote
checks the Independent Reviewer also verifies the original evidence separately.
This intentionally does NOT return a fake PASS when P01 does not yet exist.
"""
import importlib
import json
import os
from pathlib import Path

import pytest

ORACLE=Path(__file__).resolve().parent/"fixtures"/"p01"/"P01_ORACLES.json"
ITEMS=json.loads(ORACLE.read_text(encoding="utf-8"))["items"]
TEST_CASES=[(row["ac_id"],s) for row in ITEMS if row["auto_test_required"] for s in row["scenarios"]]

@pytest.fixture(scope="session")
def real_p01_observer():
    bridge=os.environ.get("AIO_P01_SUT_OBSERVER")
    if not bridge:
        pytest.fail("NOT_CHECKED: isolated P01 SUT not built/bound; never fake an AC PASS",pytrace=False)
    module=importlib.import_module(bridge)
    if not hasattr(module,"observe"):
        pytest.fail("NOT_CHECKED: P01 test observer is missing observe()",pytrace=False)
    return module.observe

@pytest.mark.parametrize("ac_id,case",TEST_CASES,ids=[f"{ac}:{s['scenario_id']}" for ac,s in TEST_CASES])
def test_p01_normative_acceptance(real_p01_observer,ac_id,case):
    """An AC is PASS only when every testcase and its non-test inspections PASS."""
    obs=real_p01_observer(ac_id,{"scenario_id":case["scenario_id"], "synthetic_input":case["synthetic_input"]})
    assert isinstance(obs,dict),f"{ac_id} must return verifiable observations"
    assert obs.get("test_source")=="real_synthetic_isolated",f"{ac_id} not real isolated execution"
    expected=case["expected_observations"]
    for key,value in expected.items():
        assert key in obs,f"{ac_id}/{case['scenario_id']} lacks observation {key}"
        assert obs[key]==value,f"{ac_id}/{case['scenario_id']} incorrect observed {key}"
    # Require attributable external/OS evidence; a boolean from a mock is insufficient.
    if ac_id in {"AC-N-SEC-01.1","AC-N-SEC-03.1","AC-N-SEC-05.4","AC-ERR-03.2"}:
        assert isinstance(obs.get("evidence_ref"),str) and obs["evidence_ref"],"NOT_CHECKED without independent evidence"
