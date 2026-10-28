"""Fourteenth D5: timing, raw before/after state, independent kernel audit and gating.

Only synthetic Ed25519 keys, no production credentials, no OQ-09/A runtime PASS.
"""
import base64
import copy
import json
import time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from p01_oqa_attestation import OQAttestationError, _canon, _sha, verify_oqa_receipt
from test_p01_twelfth_review_regressions import signed_case, synthetic_response, TEST_KERNEL_AUDIT_SIGNER


def check(p,q,r,k,*, kernel_key=None, response=None):
    return verify_oqa_receipt(response if response is not None else synthetic_response(r,k),
                              p,q,attester_key=k.public_key(),
                              kernel_audit_key=TEST_KERNEL_AUDIT_SIGNER.public_key() if kernel_key is None else kernel_key)


def test_050_timestamps_of_all_syscalls_precede_attester_issuance():
    p,q,r,k=signed_case()
    assert check(p,q,r,k)
    data=json.loads(base64.b64decode(r['signer_deployment']['signing_interfaces'][0]['os_probe_artifact']['os_probe_bytes_b64']))
    assert r['issued_monotonic_ns']>=max(e['timestamp_monotonic_ns'] for e in data['syscall_attempts'])
    r['issued_monotonic_ns']=q['challenge_start_ns']
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        check(p,q,r,k)


def test_051_two_equal_forged_write_digests_are_rejected():
    p,q,r,k=signed_case()
    ob=r['readonly_observer_deployment']
    assert check(p,q,r,k)
    ob['write_probe_bytes_before_sha256']='e'*64
    ob['write_probe_bytes_after_sha256']='e'*64
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        check(p,q,r,k)


def test_051_change_actual_after_bytes_and_rehash_attester_is_rejected():
    p,q,r,k=signed_case(); ob=r['readonly_observer_deployment']
    doc=json.loads(base64.b64decode(ob['os_probe_artifact']['os_probe_bytes_b64']))
    doc['write_denial_state']['after_b64']=base64.b64encode(b'changed witness bytes').decode()
    raw=_canon(doc)
    ob['os_probe_artifact']={'os_probe_bytes_b64':base64.b64encode(raw).decode()}
    ob['os_probe_evidence_sha256']=_sha(raw)
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        check(p,q,r,k)


@pytest.mark.parametrize('mutation',['missing_audit','wrong_audit_key','wrong_audit_digest',
                                      'wrong_audit_run','unsigned_extra_endpoint',
                                      'audit_claims_missing_events','audit_claims_losses',
                                      'audit_event_removed','audit_extra_endpoint'])
def test_052_no_self_signed_attester_claims_without_kernel_audit(mutation):
    p,q,r,k=signed_case()
    assert check(p,q,r,k)
    response=synthetic_response(r,k)
    audit=response['kernel_audit']
    if mutation=='missing_audit':
        response.pop('kernel_audit')
    elif mutation=='wrong_audit_key':
        outsider=Ed25519PrivateKey.generate().public_key()
        with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
            check(p,q,r,k,kernel_key=outsider,response=response)
        return
    elif mutation=='wrong_audit_digest':
        audit['receipt']['event_digest_set_sha256']='0'*64
    elif mutation=='wrong_audit_run':
        audit['receipt']['run_id']='elsewhere'
    elif mutation=='unsigned_extra_endpoint':
        extra=copy.deepcopy(response['receipt']['signer_deployment']['signing_interfaces'][0])
        extra['target']='/alternate-synthetic-signer.sock'
        response['receipt']['signer_deployment']['signing_interfaces'].append(extra)
        response['signature']=k.sign(_canon(response['receipt'])).hex()
    elif mutation=='audit_claims_missing_events':
        audit['receipt']['all_signing_endpoints_observed']=False
    elif mutation=='audit_claims_losses':
        audit['receipt']['event_loss_count']=1
    elif mutation=='audit_event_removed':
        audit['receipt']['kernel_syscall_events'].pop()
    elif mutation=='audit_extra_endpoint':
        audit['receipt']['discovered_signing_endpoints'].append('/unknown/test-broker')
    if mutation!='missing_audit':
        audit['signature']=TEST_KERNEL_AUDIT_SIGNER.sign(_canon(audit['receipt'])).hex()
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        check(p,q,r,k,response=response)


def test_053_normative_comparison_is_deferred_until_after_kernel_closure(tmp_path):
    import inspect
    from p01_probe import (TestRun,IndependentProof,ProbeError,_canonical,_sha256,
        _run_identity,_evidence_mac,verify_independent_proofs,
        verify_normative_measurements,verify_execution_closure)
    workspace=tmp_path/'workspace';workspace.mkdir()
    protected=tmp_path/'trusted_evidence';protected.mkdir()
    raw={'operation':'synthetic_precedence'}
    key=b'test-only-witness-authority-key-32-bytes'
    run=TestRun(pid=2817,returncode=0,command_digest='b'*64,
        fixture_digest=_sha256(_canonical(raw)),workspace=workspace,git_sha='a'*40,
        run_id='synthetic-run',process_start_ticks=11,process_pids=(2817,),
        returncodes=(0,),collector_sha256='c'*64)
    capture={'value':99}
    path=protected/'sqlite_snapshot.json'
    path.write_bytes(_canonical({'schema':'aio.p01.independent_witness.v1',
        'source':'sqlite_snapshot','run':_run_identity(run),'measurement':capture}))
    kw=dict(source='sqlite_snapshot',path=path,sha256=_sha256(path.read_bytes()),
        captures=capture,run_pid=run.pid,fixture_digest=run.fixture_digest,
        witness_mac='',run_id=run.run_id,git_sha=run.git_sha,
        run_command_digest=run.command_digest,run_returncode=run.returncode,
        process_start_ticks=run.process_start_ticks)
    unsigned=IndependentProof(**kw)
    proof=IndependentProof(**{**kw,'witness_mac':_evidence_mac(key,unsigned)})
    case={'synthetic_input':raw,'independent_proofs':[{'source':'sqlite_snapshot','required':True}],
          'expected_observations':{'value':1}}
    args=dict(trusted_witness_key=key,expected_git_sha=run.git_sha,
              expected_command_digest=run.command_digest,
              expected_collector_sha256=run.collector_sha256)
    with pytest.raises(ProbeError,match='FAIL'):
        verify_independent_proofs(case,{}, {'sqlite_snapshot':proof}, run, **args)
    observed=verify_independent_proofs(case,{}, {'sqlite_snapshot':proof},run,
                                      evaluate_expected=False, **args)
    assert observed['value']==99
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_execution_closure({},approved_components_sha256={'/synthetic/bin':'a'*64},
                                 process_pids=(2817,))
    with pytest.raises(ProbeError,match='FAIL'):
        verify_normative_measurements(case,observed,run)


def test_053_acceptance_requires_closure_before_normative_result():
    """Control-flow assertion against the actual acceptance function source."""
    from pathlib import Path
    acceptance=Path(__file__).with_name('test_p01_acceptance.py')
    if not acceptance.is_file():
        pytest.skip('full acceptance driver unavailable in local restored test seam')
    source=acceptance.read_text()
    first=source.index('observations=verify_independent_proofs(')
    second=source.index('verify_execution_closure(',first)
    third=source.index('verify_normative_measurements(required_case,observations,run)',second)
    assert first < second < third
    assert 'evaluate_expected=False' in source[first:second]
