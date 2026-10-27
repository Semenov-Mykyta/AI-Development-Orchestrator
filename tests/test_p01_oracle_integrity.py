"""Executable D5 *oracle metadata* consistency checks (NOT SUT acceptance)."""
import json
from pathlib import Path

ORACLE = Path(__file__).resolve().parent / "fixtures" / "p01" / "P01_ORACLES.json"
AC_IDS = {
 "AC-F-01.1", "AC-F-02.1", "AC-F-03.1", "AC-F-04.1", "AC-F-05.1", "AC-F-06.1",
 "AC-F-07.1", "AC-F-34.1", "AC-N-10.1", "AC-F-31.1", "AC-N-15.1", "AC-N-15.2",
 "AC-ERR-03.1", "AC-ERR-03.2", "AC-N-12.1", "AC-N-12.2", "AC-N-12.3",
 "AC-N-SEC-01.1", "AC-N-SEC-02.1", "AC-N-SEC-02.2", "AC-N-SEC-03.1",
 "AC-N-SEC-04.1", "AC-N-SEC-05.1", "AC-N-SEC-05.2", "AC-N-SEC-05.3",
 "AC-N-SEC-05.4", "AC-N-SEC-05.5"
}
INSPECTION_ONLY = {"AC-N-SEC-02.1", "AC-N-SEC-05.1", "AC-N-SEC-05.3"}
MIXED = {"AC-N-10.1", "AC-N-SEC-05.5"}

def load():
    return json.loads(ORACLE.read_text(encoding="utf-8"))

def test_d5_exact_27_unique_ac_ids():
    rows=load()["items"]
    assert len(rows)==27
    assert len({row["ac_id"] for row in rows})==27
    assert {row["ac_id"] for row in rows}==AC_IDS
    assert len({row["requirement"] for row in rows})==18

def test_d5_method_preservation_and_automated_scenarios():
    rows=load()["items"]
    for row in rows:
        ac=row["ac_id"]
        assert row["auto_test_required"]==("Т" in row["method"]),ac
        assert bool(row["scenarios"]) == (ac not in INSPECTION_ONLY),ac
        assert row["independent_inspection_required"]==(ac in INSPECTION_ONLY|MIXED),ac
        assert row["ac_status"]=="NOT_CHECKED",ac
        assert all(s["sut_execution_status"]=="NOT_CHECKED" for s in row["scenarios"])

def test_d5_mandatory_negative_sets():
    items={r["ac_id"]:r for r in load()["items"]}
    assert len(items["AC-N-12.1"]["scenarios"])==5
    assert len(items["AC-N-12.3"]["scenarios"])==2
    cases={s["scenario_id"] for s in items["AC-N-SEC-05.5"]["scenarios"]}
    assert len(cases)==9 # eight classes; fourth class split into two independent missing-field cases
    assert {"exactly-next-due","after-next-due","old-ref-after-replacement","new-ref-valid-scope"} <= cases
    assert len(items["AC-N-SEC-05.4"]["scenarios"])==4

def test_d5_no_manual_inspection_claimed_as_test_pass():
    rows=load()["items"]
    assert not any(r["ac_status"]=="PASS" for r in rows)
    for r in rows:
        if r["ac_id"] in INSPECTION_ONLY:
            assert r["scenarios"]==[]


def test_d5_credential_clock_boundary_is_exact_utc_not_rounded():
    from datetime import datetime, timedelta, timezone
    case_rows = next(x for x in load()["items"] if x["ac_id"] == "AC-N-SEC-05.5")["scenarios"]
    by_name={x["scenario_id"]:x for x in case_rows}
    for item in case_rows:
        data=item["synthetic_input"]
        now=datetime.fromisoformat(data["now_utc"])
        assert now.tzinfo == timezone.utc
        if data.get("last_rotated_at"):
            rotated=datetime.fromisoformat(data["last_rotated_at"])
            assert rotated.tzinfo == timezone.utc
            due=rotated + timedelta(days=90)
            if data.get("next_due_at"):
                assert datetime.fromisoformat(data["next_due_at"])<=due
        if data.get("expires_at"):
            expiry=datetime.fromisoformat(data["expires_at"])
            assert datetime.fromisoformat(data["next_due_at"])<=expiry
    assert datetime.fromisoformat(by_name["exactly-next-due"]["synthetic_input"]["next_due_at"])==datetime.fromisoformat(by_name["exactly-next-due"]["synthetic_input"]["now_utc"])
    assert by_name["exactly-next-due"]["expected_observations"]["decision"]=="DENY"
    assert by_name["before-due-valid-scope"]["expected_observations"]["decision"]=="ALLOW"


def test_d5_frozen_candidate_fixture_digest():
    """Flags ANY fixture mutation after this review candidate snapshot.

    D5 Reviewer must independently inspect expected values against normative SPEC;
    this hash only catches accidental/post-review edits, not semantic correctness.
    """
    import hashlib
    value=load()
    canonical=json.dumps(value['items'],sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf8')
    assert hashlib.sha256(canonical).hexdigest()=="8a3e37ecda34f18199dcc812ae9baed43f42e667fd60b863dfabfd61542f3ce3"
