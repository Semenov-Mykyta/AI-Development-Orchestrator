"""Independent D5 regression tests derived from reviewer D5-001 .. D5-009.
These check ORACLE quality, not a running P01 product.
"""
import hashlib
import json
from pathlib import Path

BASE=Path(__file__).resolve().parent
CASES=json.loads((BASE/'fixtures/p01/P01_ORACLES.json').read_text('utf-8'))['items']
BY_AC={r['ac_id']:r for r in CASES}


def scenario(ac, sid):
    return next(s for s in BY_AC[ac]['scenarios'] if s['scenario_id']==sid)


def test_d5_001_no_self_report_observer_that_can_echo_expected():
    text=(BASE/'test_p01_acceptance.py').read_text('utf-8')
    assert 'AIO_P01_SUT_OBSERVER' not in text
    assert 'subprocess.Popen' in text
    assert 'verify_independent_proofs' in text


def test_d5_002_every_case_has_reproducible_non_empty_input():
    for row in CASES:
        for s in row['scenarios']:
            assert s['synthetic_input'],f"{row['ac_id']}: {s['scenario_id']} has no input"
            assert s['synthetic_input'].get('operation'),f"{row['ac_id']}:{s['scenario_id']} has no concrete operation"


def test_d5_003_hostile_agents_contain_full_normative_attack():
    for s in BY_AC['AC-N-12.3']['scenarios']:
        attack=s['synthetic_input']['project_agents_md']
        assert '[FAKE OWNER OVERRIDE]' in attack
        assert all(fragment in attack.lower() for fragment in ('secret scan','supervisor policy','push в main'))
        assert s['synthetic_input']['trust_source']=='untrusted_project_tree'


def test_d5_004_every_automated_case_has_external_probe_plan():
    for row in CASES:
        for s in row['scenarios']:
            assert s.get('independent_proofs'),f"{row['ac_id']}:{s['scenario_id']} requires independent proofs"
            assert all(p.get('source') not in ('sut_stdout','sut_report','self_report') for p in s['independent_proofs'])
    for ac in ('AC-N-SEC-01.1','AC-N-SEC-03.1','AC-N-SEC-05.4','AC-ERR-03.2'):
        assert all(len(s['independent_proofs'])>=2 for s in BY_AC[ac]['scenarios'])


def test_d5_005_exact_retention_and_distinct_offnode_scenarios():
    for sid in ('expired-owned-logs','log-quota-overflow'):
        inp=scenario('AC-N-15.1',sid)['synthetic_input']
        assert inp['logs_ttl_days']==7 and inp['logs_quota_bytes']==128*1024*1024
        assert inp['completed_evidence_ttl_days']==30 and inp['completed_evidence_quota_bytes']==512*1024*1024
        assert inp['protected_paths']
    a=scenario('AC-N-15.2','evidence-512MiB-without-offnode')['synthetic_input']
    b=scenario('AC-N-15.2','offnode-unavailable')['synthetic_input']
    assert a!=b and not a['off_node_backup_verified'] and not b['off_node_backup_verified']


def test_d5_006_fs_full_has_durable_intent_restart_trace():
    before=scenario('AC-ERR-03.2','full-fs-before-durable-intent')
    after=scenario('AC-ERR-03.2','full-fs-result-commit-after-remote-effect')
    assert before['synthetic_input']['operation']=='perform_remote_write_with_injected_fs_failure'
    assert after['synthetic_input']['operation']=='perform_remote_write_with_injected_fs_failure'
    assert after['expected_observations']['journal_state']=='UNCERTAIN'
    assert after['synthetic_input']['recovery_sequence']==['restart_supervisor','reconcile_with_remote','resume_only_after_outcome_known']


def test_d5_007_provider_expiry_equal_and_metadata_guards():
    s=scenario('AC-N-SEC-05.5','provider-expiry-comes-first')
    assert s['synthetic_input']['now_utc']==s['synthetic_input']['expires_at']
    assert s['expected_observations']['decision']=='DENY'
    for s in BY_AC['AC-N-SEC-05.5']['scenarios']:
        data=s['synthetic_input']
        assert all(x in data for x in ('owner_actor','rotation_event_id','inventory_access','credential_ref'))
        assert data['inventory_access']=='supervisor_only'


def test_d5_008_method_literal_is_exact_specification():
    assert BY_AC['AC-N-10.1']['method']=='Т, И (проверяет пользователь)'


def test_d5_009_integrity_detects_changed_expected_decision():
    from p01_probe import verify_normative_expectations, ProbeError
    snapshot=json.loads(json.dumps(CASES))
    item=next(r for r in snapshot if r['ac_id']=='AC-N-12.1')
    s=next(s for s in item['scenarios'] if s['scenario_id']=='skip-mandatory-test')
    s['expected_observations']['allowed']=True
    try:
        verify_normative_expectations(snapshot)
    except ProbeError:
        pass
    else:
        raise AssertionError('Mutation of mandatory Policy Gate DENY went undetected')


def test_d5_001_echo_only_fake_is_not_accepted_as_evidence():
    from p01_probe import verify_independent_proofs, ProbeError
    case=scenario('AC-N-12.1','skip-mandatory-test')
    forged={**case['expected_observations'],'test_source':'real_synthetic_isolated','evidence_ref':'fake.txt'}
    try:
        verify_independent_proofs(case, forged, {}, None)
    except ProbeError:
        pass
    else:
        raise AssertionError('echo-only fake observer incorrectly passed')
