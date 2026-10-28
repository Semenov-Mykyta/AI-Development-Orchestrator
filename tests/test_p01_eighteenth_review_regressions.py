"""Synthetic EIGHTEENTH-D5-061/062 regressions. Never runtime AC evidence."""
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from p01_probe import (IndependentProof, ProbeError, TestRun, _canonical,
    _sha256, _run_identity, _evidence_mac, _parse_witness,
    verify_independent_proofs, verify_normative_measurements)
from p01_oqa_attestation import (_canon as attester_canon,
    verify_readonly_observer_measurements)

KEY=b'only-synthetic-hmac-key-for-061-regressions'

def make_run(tmp):
    ws=tmp/'workspace';ws.mkdir()
    (tmp/'trusted_evidence').mkdir()
    fixture={'operation':'synthetic-evidence-check'}
    run=TestRun(pid=1527,returncode=0,command_digest='b'*64,
        fixture_digest=_sha256(_canonical(fixture)),workspace=ws,
        git_sha='a'*40,run_id='unit-run',process_start_ticks=17,
        process_pids=(1527,),returncodes=(0,),collector_sha256='c'*64)
    return run,fixture

def signed_capture(source,measurement,signer):
    receipt={'schema':'aio.p01.observer.snapshot.v1',
        'observer_id':'synthetic-observer','source':source,
        'run_id':'unit-run','git_sha':'a'*40,'command_digest':'b'*64,
        'measurement_sha256':_sha256(_canonical(measurement)),
        'readonly':True,'origin':'trusted_os_broker'}
    return {**measurement,'readonly_observer_receipt':{
        'receipt':receipt,'signature':signer.sign(attester_canon(receipt)).hex()}}

def proof_for(tmp,run,source,raw,capture):
    path=tmp/'trusted_evidence'/f'{source}.json'
    path.write_bytes(json.dumps({'schema':'aio.p01.independent_witness.v1',
        'source':source,'run':_run_identity(run),'measurement':raw},
        sort_keys=True,separators=(',',':')).encode())
    fields=dict(source=source,path=path,sha256=_sha256(path.read_bytes()),
        captures=capture,run_pid=run.pid,fixture_digest=run.fixture_digest,
        witness_mac='',run_id=run.run_id,git_sha=run.git_sha,
        run_command_digest=run.command_digest,run_returncode=run.returncode,
        process_start_ticks=run.process_start_ticks)
    draft=IndependentProof(**fields)
    return IndependentProof(**{**fields,'witness_mac':_evidence_mac(KEY,draft)})

def check(run,fixture,evidence,expected,*,defer=False):
    return verify_independent_proofs({'synthetic_input':fixture,
        'independent_proofs':[{'source':s,'required':True} for s in evidence],
        'expected_observations':expected},{},evidence,run,
        trusted_witness_key=KEY,expected_git_sha=run.git_sha,
        expected_command_digest=run.command_digest,
        expected_collector_sha256=run.collector_sha256,
        evaluate_expected=not defer)

@pytest.mark.parametrize(('signed','file_value'),[
    (0,False),(False,0),(True,1),(1,True),
    ({'nest':[True,0]},{'nest':[1,False]}),(1.0,1)],
    ids=['int-false','false-int','true-one','one-true','nested','float-int'])
def test_061_signed_capture_vs_raw_witness_wrong_json_type(tmp_path,signed,file_value):
    run,fixture=make_run(tmp_path)
    signer=Ed25519PrivateKey.generate()
    source='sqlite_snapshot'
    capture=signed_capture(source,{'value':signed},signer)
    raw={**{'value':file_value},'readonly_observer_receipt':capture['readonly_observer_receipt']}
    proof=proof_for(tmp_path,run,source,raw,capture)
    assert verify_readonly_observer_measurements({source:proof},
        observer_key=signer.public_key(),observer_id='synthetic-observer',
        run_id=run.run_id,git_sha=run.git_sha,command_digest=run.command_digest)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        check(run,fixture,{source:proof},{'value':file_value})

@pytest.mark.parametrize(('one','two'),[(False,0),(0,False),(True,1),(1,True),
    ({'nest':[False]},{'nest':[0]})])
def test_061_conflicting_signed_sources_rejected(tmp_path,one,two):
    run,fixture=make_run(tmp_path)
    signer=Ed25519PrivateKey.generate();evidence={}
    for source,value in zip(('sqlite_snapshot','subprocess_audit'),(one,two)):
        capture=signed_capture(source,{'shared':value},signer)
        evidence[source]=proof_for(tmp_path,run,source,capture,capture)
    assert verify_readonly_observer_measurements(evidence,
        observer_key=signer.public_key(),observer_id='synthetic-observer',
        run_id=run.run_id,git_sha=run.git_sha,command_digest=run.command_digest)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        check(run,fixture,evidence,{'shared':two},defer=True)

def test_061_two_matching_signed_observations_still_merge(tmp_path):
    run,fixture=make_run(tmp_path)
    signer=Ed25519PrivateKey.generate(); evidence={}
    for source in ('sqlite_snapshot','subprocess_audit'):
        capture=signed_capture(source,{'shared':False},signer)
        evidence[source]=proof_for(tmp_path,run,source,capture,capture)
    assert verify_readonly_observer_measurements(evidence,
        observer_key=signer.public_key(),observer_id='synthetic-observer',
        run_id=run.run_id,git_sha=run.git_sha,command_digest=run.command_digest)
    assert check(run,fixture,evidence,{'shared':False})['shared'] is False

@pytest.mark.parametrize('number',[float('nan'),float('inf'),-float('inf')])
def test_062_nonfinite_quota_never_passes(tmp_path,number):
    run,fixture=make_run(tmp_path)
    case={'synthetic_input':fixture,
        'expected_observations':{'owned_log_bytes_after':{'op':'at_most','value':134217728}}}
    with pytest.raises(ProbeError,match='FAIL'):
        verify_normative_measurements(case,{'owned_log_bytes_after':number},run)

@pytest.mark.parametrize(('number','pass_expected'),[(0,True),(100.5,True),
    (134217728,True),(134217729,False),(-1,False),(True,False)])
def test_062_finite_quota_positive_and_negative(tmp_path,number,pass_expected):
    run,fixture=make_run(tmp_path)
    case={'synthetic_input':fixture,
        'expected_observations':{'owned_log_bytes_after':{'op':'at_most','value':134217728}}}
    if pass_expected:
        assert verify_normative_measurements(case,{'owned_log_bytes_after':number},run)['owned_log_bytes_after']==number
    else:
        with pytest.raises(ProbeError,match='FAIL'):
            verify_normative_measurements(case,{'owned_log_bytes_after':number},run)

@pytest.mark.parametrize('token',['NaN','Infinity','-Infinity'])
def test_062_nonstandard_json_token_rejected_in_witness(tmp_path,token):
    run,fixture=make_run(tmp_path)
    path=tmp_path/'trusted_evidence'/'sqlite_snapshot.json'
    prefix=json.dumps({'schema':'aio.p01.independent_witness.v1',
        'source':'sqlite_snapshot','run':_run_identity(run)},separators=(',',':'))
    path.write_text(prefix[:-1]+',"measurement":{"quota":'+token+'}}')
    proof=IndependentProof(source='sqlite_snapshot',path=path,
        sha256=_sha256(path.read_bytes()),captures={'quota':0},run_pid=run.pid,
        fixture_digest=run.fixture_digest,witness_mac='',run_id=run.run_id,
        git_sha=run.git_sha,run_command_digest=run.command_digest,
        run_returncode=run.returncode,process_start_ticks=run.process_start_ticks)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        _parse_witness(proof,run)

@pytest.mark.parametrize('value',[float('nan'),float('inf'),-float('inf')])
def test_062_nonfinite_json_cannot_be_serialized(value):
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        _canonical({'quota':value})
