"""SEVENTEENTH-D5-059/060: synthetic authority and authenticated AC types.

Only test keys and fake SUT-independent measurements; never production access.
"""
import hashlib
import os
from pathlib import Path
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

from p01_oqa_attestation import OQAttestationError, validate_oqa_policy, require_live_oqa_attestation
from p01_probe import ProbeError, TestRun, verify_normative_measurements
from test_p01_twelfth_review_regressions import policy as sample_oqa_policy


def _pem(public_key):
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _test_run(tmp_path):
    return TestRun(pid=77,returncode=0,command_digest='b'*64,
                   fixture_digest='a'*64,workspace=tmp_path)


def test_059_four_distinct_pem_digests_same_key_denied_before_attester_rpc(monkeypatch):
    if os.geteuid()!=0:
        pytest.skip('root-owned synthetic key namespace requires isolated root runner')
    key=Ed25519PrivateKey.generate().public_key()
    base=_pem(key)
    variants=[base,base+b'\n',base.replace(b'\n',b'\r\n'),base+b'\n\n']
    assert len({hashlib.sha256(x).hexdigest() for x in variants})==4
    assert len({load_pem_public_key(x).public_bytes(Encoding.Raw,PublicFormat.Raw) for x in variants})==1
    with tempfile.TemporaryDirectory(dir='/root',prefix='aio-059-synthetic-') as folder:
        root=Path(folder)
        p=sample_oqa_policy()
        for prefix,data in zip(('oqa_attester','readonly_observer','kernel_monitor','oqa_kernel_audit'),variants):
            path=root/(prefix+'.pem')
            path.write_bytes(data)
            path.chmod(0o600)
            p[prefix+'_public_key_path']=str(path)
            p[prefix+'_public_key_sha256']=hashlib.sha256(data).hexdigest()
        # Old digest-only separation passes these four syntactically distinct encodings.
        assert validate_oqa_policy(p)
        monkeypatch.setattr('p01_oqa_attestation._receive_attester',
                            lambda *args,**kw: pytest.fail('key identity bypass reached attester RPC'))
        with pytest.raises(OQAttestationError,match='NOT_CHECKED.*(identit|distinct|key)'):
            require_live_oqa_attestation(p,run_id='synthetic-run',git_sha='a'*40,
                                         command_digest='b'*64,
                                         required_sources=['filesystem_snapshot'])


def test_059_positive_four_cryptographically_distinct_keys():
    from p01_oqa_attestation import require_distinct_oqa_signing_keys
    keys=[Ed25519PrivateKey.generate().public_key() for _ in range(4)]
    assert require_distinct_oqa_signing_keys(*keys) is True
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        require_distinct_oqa_signing_keys(keys[0],keys[1],keys[0],keys[3])


@pytest.mark.parametrize(('expected','observed'),[
    (0,False),(1,True),(False,0),(True,1),
    ({'calls':0},{'calls':False}),([True,0],[1,False]),
    (0,0.0),(1,1.0),(0.0,0),
    ({'nested':{'allowed':True}},{'nested':{'allowed':1}}),
    (None,False),('0',0),
],ids=['zero-vs-false','one-vs-true','false-vs-zero','true-vs-one',
       'nested-dict','nested-list','int-vs-float-zero','int-vs-float-one',
       'float-vs-int','nested-boolean','null-vs-false','str-vs-int'])
def test_060_normative_json_type_confusion_is_fail(tmp_path,expected,observed):
    case={'synthetic_input':{},'expected_observations':{'field':expected}}
    with pytest.raises(ProbeError,match='FAIL'):
        verify_normative_measurements(case,{'field':observed},_test_run(tmp_path))


@pytest.mark.parametrize('value',[0,1,False,True,1.5,'x',None,{'calls':[True,0]},[False,1]])
def test_060_normative_same_type_and_value_positive(tmp_path,value):
    case={'synthetic_input':{},'expected_observations':{'field':value}}
    assert verify_normative_measurements(case,{'field':value},_test_run(tmp_path))['field']==value


@pytest.mark.parametrize(('observed','ok'),[(True,False),(False,False),(10,True),(10.0,True),(11,False),(-1,False)])
def test_060_at_most_disallows_bool_preserves_numeric_quota(tmp_path,observed,ok):
    case={'synthetic_input':{},'expected_observations':{'quota':{'op':'at_most','value':10}}}
    if ok:
        assert verify_normative_measurements(case,{'quota':observed},_test_run(tmp_path))['quota']==observed
    else:
        with pytest.raises(ProbeError,match='FAIL'):
            verify_normative_measurements(case,{'quota':observed},_test_run(tmp_path))


@pytest.mark.parametrize(('expected','measured'),[(0,False),(True,1),(False,0)],
                         ids=['signed-false-for-zero','signed-one-for-true','signed-zero-for-false'])
def test_060_authenticated_independent_witness_cannot_mask_wrong_json_type(tmp_path,expected,measured):
    """Correct HMAC+SHA+run binding must not authorize a mismatched JSON type."""
    from p01_probe import (IndependentProof,_canonical,_sha256,
                           _run_identity,_evidence_mac,verify_independent_proofs)
    import hashlib
    import os
    workspace=tmp_path/'workspace';workspace.mkdir()
    evidence_dir=tmp_path/'trusted_evidence';evidence_dir.mkdir()
    fixture={'operation':'synthetic-measurement-validation'}
    run=TestRun(pid=7871,returncode=0,command_digest='b'*64,
        fixture_digest=_sha256(_canonical(fixture)),workspace=workspace,
        git_sha='a'*40,run_id='synthetic-signed-run',process_start_ticks=145,
        process_pids=(7871,),returncodes=(0,),collector_sha256='c'*64)
    source='sqlite_snapshot'
    capture={'field':measured}
    fp=evidence_dir/(source+'.json')
    fp.write_bytes(_canonical({'schema':'aio.p01.independent_witness.v1',
                               'source':source,'run':_run_identity(run),'measurement':capture}))
    fields=dict(source=source,path=fp,sha256=_sha256(fp.read_bytes()),
        captures=capture,run_pid=run.pid,fixture_digest=run.fixture_digest,
        witness_mac='',run_id=run.run_id,git_sha=run.git_sha,
        run_command_digest=run.command_digest,run_returncode=run.returncode,
        process_start_ticks=run.process_start_ticks)
    key=b'synthetic-authority-test-witness-key-32+'
    unsealed=IndependentProof(**fields)
    proof=IndependentProof(**{**fields,'witness_mac':_evidence_mac(key,unsealed)})
    case={'synthetic_input':fixture,
          'independent_proofs':[{'source':source,'required':True}],
          'expected_observations':{'field':expected}}
    with pytest.raises(ProbeError,match='FAIL'):
        verify_independent_proofs(case,{}, {source:proof},run,
             trusted_witness_key=key,expected_git_sha=run.git_sha,
             expected_command_digest=run.command_digest,
             expected_collector_sha256=run.collector_sha256)


def test_059_four_distinct_pinned_keys_pass_cryptographic_admission(monkeypatch):
    if os.geteuid()!=0:
        pytest.skip('root-owned synthetic key namespace requires isolated root runner')
    class AttesterCalled(Exception):
        pass
    with tempfile.TemporaryDirectory(dir='/root',prefix='aio-059-distinct-test-') as folder:
        root=Path(folder)
        p=sample_oqa_policy()
        for prefix in ('oqa_attester','readonly_observer','kernel_monitor','oqa_kernel_audit'):
            raw=_pem(Ed25519PrivateKey.generate().public_key())
            path=root/(prefix+'.pem');path.write_bytes(raw);path.chmod(0o600)
            p[prefix+'_public_key_path']=str(path)
            p[prefix+'_public_key_sha256']=hashlib.sha256(raw).hexdigest()
        assert validate_oqa_policy(p)
        monkeypatch.setattr('p01_oqa_attestation._protected_observer_socket',lambda *a,**k: None)
        def probe_service(*a,**k):
            raise AttesterCalled('all four root-pinned public keys were distinct')
        monkeypatch.setattr('p01_oqa_attestation._receive_attester',probe_service)
        with pytest.raises(AttesterCalled):
            require_live_oqa_attestation(p,run_id='synthetic-run',git_sha='a'*40,
                                         command_digest='b'*64,
                                         required_sources=['filesystem_snapshot'])
