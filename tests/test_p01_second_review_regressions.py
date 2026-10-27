"""Reviewer NEW-D5-010..017 red/green checks; oracle quality, not SUT PASS."""
import hashlib
import json
from pathlib import Path

import pytest

from p01_probe import IndependentProof, ProbeError, TestRun, verify_independent_proofs, _canonical, _evidence_mac

ROOT = Path(__file__).parent
ITEMS = json.loads((ROOT / 'fixtures/p01/P01_ORACLES.json').read_text('utf-8'))['items']

def case(ac, scenario):
    return next(s for row in ITEMS if row['ac_id'] == ac for s in row['scenarios'] if s['scenario_id'] == scenario)


def test_new_d5_010_fail_closed_is_not_a_journal_state():
    s = case('AC-ERR-03.2','full-fs-before-durable-intent')
    assert s['expected_observations'].get('system_mode') == 'FAIL_CLOSED'
    assert s['expected_observations'].get('journal_state') != 'FAIL_CLOSED'
    assert s['expected_observations']['remote_write_calls'] == 0


def test_new_d5_011_128mib_log_overflow_must_be_enforced():
    s = case('AC-N-15.1','log-quota-overflow')
    exp = s['expected_observations']
    assert exp.get('owned_log_bytes_after') is not None
    assert exp['owned_log_bytes_after'] == {'op':'at_most','value':s['synthetic_input']['logs_quota_bytes']}
    assert exp.get('log_quota_enforced') is True


def test_new_d5_012_post_remote_fault_must_have_exactly_one_real_write():
    s=case('AC-ERR-03.2','full-fs-result-commit-after-remote-effect')
    exp=s['expected_observations']
    assert exp.get('remote_writes_total_after_restart') == 1
    assert exp.get('remote_writes_before_restart') == 1
    assert exp.get('duplicate_remote_writes_after_restart') == 0
    assert exp.get('journal_state') == 'UNCERTAIN'


@pytest.mark.parametrize('scenario_id', ['forbidden-supervisor-path-os-denial','forbidden-production-namespace-os-denial','forbidden-network-endpoint-os-denial'])
def test_new_d5_013_os_error_is_externally_measured_not_generic_failure(scenario_id):
    s=case('AC-N-SEC-05.4',scenario_id)
    exp=s['expected_observations']
    assert exp.get('actual_errno') == s['synthetic_input']['expect_errno']
    assert exp.get('actual_syscall') == s['synthetic_input']['attempt']
    assert exp.get('denied_target') == s['synthetic_input']['target']


def test_new_d5_014_credential_denials_block_all_outbound_actions():
    row=next(r for r in ITEMS if r['ac_id']=='AC-N-SEC-05.5')
    for s in row['scenarios']:
        if s['expected_observations']['decision']=='DENY':
            assert s['expected_observations'].get('outbound_calls')==0, s['scenario_id']
            assert any(p['source']=='outbound_call_counter' for p in s['independent_proofs'])


def test_new_d5_015_acceptance_has_explicit_trusted_collector_hook():
    source=(ROOT/'test_p01_acceptance.py').read_text('utf-8')
    assert 'collect_trusted_evidence' in source
    assert 'verify_independent_proofs(case, {}, {}, run)' not in source
    assert 'AIO_P01_APPROVED_COLLECTOR' in source


def test_new_d5_016_proof_must_bind_sha_command_returncode_and_run_id(tmp_path):
    source=(ROOT/'p01_probe.py').read_text('utf-8')
    for anchor in ('git_sha', 'run_id', 'run_command_digest', 'run_returncode', 'process_start_ticks'):
        assert anchor in source
    assert 'observations = json.loads(proof.path.read_bytes())' in source or 'json.loads(proof.path.read_text' in source


def test_new_d5_017_idempotency_executes_two_real_calls_in_one_workspace():
    c=case('AC-F-01.1','same-idempotency-key-again')
    seq=c['synthetic_input'].get('sequence')
    assert seq is not None and len(seq)==2
    assert [step['idempotency_key'] for step in seq]==['reg-1','reg-1']
    source=(ROOT/'test_p01_acceptance.py').read_text('utf-8')
    assert 'for step in steps' in source
    assert 'same-idempotency-key-again' not in source or 'prior_submission_count' not in source


def test_new_d5_016_capture_mismatch_against_signed_witness_bytes_denied(tmp_path):
    fixture={'operation':'test'}
    # Synthetic verifier-only setup; never describes an actual SUT execution.
    from p01_probe import TestRun
    run=TestRun(pid=4817,returncode=0,command_digest='a'*64,
                fixture_digest=hashlib.sha256(_canonical(fixture)).hexdigest(), workspace=tmp_path/'workspace')
    run.workspace.mkdir()
    e=tmp_path/'trusted_evidence';e.mkdir()
    path=e/'fake.json';path.write_bytes(_canonical({'source':'filesystem_snapshot','measurement':{'foo':0}}))
    key=b'synthetic-verifier-unit-key-not-a-prod-secret-123456'
    proof=IndependentProof(source='filesystem_snapshot',path=path,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                           captures={'foo':1},run_pid=run.pid,fixture_digest=run.fixture_digest,witness_mac='')
    signed=IndependentProof(**{**vars(proof),'witness_mac':_evidence_mac(key,proof)})
    c={'synthetic_input':fixture,'expected_observations':{'foo':1},'independent_proofs':[{'source':'filesystem_snapshot'}]}
    with pytest.raises(ProbeError):
        verify_independent_proofs(c,{}, {'filesystem_snapshot':signed},run,trusted_witness_key=key)
