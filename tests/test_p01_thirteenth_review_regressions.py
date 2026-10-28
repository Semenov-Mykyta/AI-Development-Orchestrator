"""Thirteenth D5 review: multi-source observer positives and primary OS-probe integrity.

All keys/receipts and Linux events in this file are SYNTHETIC TEST FIXTURES.
No valid OQ-09/A kernel evidence or P01 runtime AC is claimed.
"""
import base64
import copy
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from p01_oqa_attestation import (OQAttestationError, _canon, _sha,
    verify_oqa_receipt, verify_readonly_observer_measurements)
from test_p01_twelfth_review_regressions import signed_case


def _signed_snapshot(signer, *, source, measured, run_id='synthetic-run',
                     git_sha='a'*40, command_digest='b'*64):
    receipt={'schema':'aio.p01.observer.snapshot.v1',
             'observer_id':'independent-test-observer','source':source,
             'run_id':run_id,'git_sha':git_sha,'command_digest':command_digest,
             'measurement_sha256':_sha(_canon(measured)),
             'readonly':True,'origin':'trusted_os_broker'}
    return {**measured,'readonly_observer_receipt':{
        'receipt':receipt,'signature':signer.sign(_canon(receipt)).hex()}}


def test_048_two_distinct_observer_receipts_are_verified_and_merge_only_measurements(tmp_path):
    """REAL verifier path, not a mock merger; metadata stays on each source proof."""
    from p01_probe import (IndependentProof,TestRun,_canonical,_sha256,
                           _run_identity,_evidence_mac,verify_independent_proofs)
    from types import SimpleNamespace
    owner=Ed25519PrivateKey.generate()
    key=b'only-synthetic-unit-test-witness-key!'  # not any real witness secret
    workspace=tmp_path/'workspace';workspace.mkdir()
    root=tmp_path/'trusted_evidence';root.mkdir()
    raw={'operation':'synthetic_multi_source_observer_test'}
    run=TestRun(pid=7101,returncode=0,command_digest='b'*64,
                fixture_digest=_sha256(_canonical(raw)),workspace=workspace,
                git_sha='a'*40,run_id='synthetic-run',process_start_ticks=101,
                process_pids=(7101,),returncodes=(0,),collector_sha256='c'*64)
    evidence={}
    for source,measure in (('sqlite_snapshot',{'sqlite_rows':3}),
                            ('subprocess_audit',{'subprocess_exit':0})):
        capture=_signed_snapshot(owner,source=source,measured=measure)
        path=root/f'{source}.json'
        path.write_bytes(_canonical({'schema':'aio.p01.independent_witness.v1',
                     'source':source,'run':_run_identity(run),'measurement':capture}))
        kwargs={'source':source,'path':path,'sha256':_sha256(path.read_bytes()),
            'captures':capture,'run_pid':run.pid,'fixture_digest':run.fixture_digest,
            'witness_mac':'','run_id':run.run_id,'git_sha':run.git_sha,
            'run_command_digest':run.command_digest,'run_returncode':run.returncode,
            'process_start_ticks':run.process_start_ticks}
        draft=IndependentProof(**kwargs)
        evidence[source]=IndependentProof(**{**kwargs,'witness_mac':_evidence_mac(key,draft)})
    scope={'observer_key':owner.public_key(),'observer_id':'independent-test-observer',
        'run_id':run.run_id,'git_sha':run.git_sha,'command_digest':run.command_digest}
    assert verify_readonly_observer_measurements(evidence,**scope)
    case={'synthetic_input':raw,'independent_proofs':[
        {'source':'sqlite_snapshot','required':True},
        {'source':'subprocess_audit','required':True}],
        'expected_observations':{'sqlite_rows':3,'subprocess_exit':0}}
    merged=verify_independent_proofs(case,{},evidence,run,trusted_witness_key=key,
                expected_git_sha=run.git_sha,expected_command_digest=run.command_digest,
                expected_collector_sha256=run.collector_sha256)
    assert merged['sqlite_rows']==3 and merged['subprocess_exit']==0
    assert 'readonly_observer_receipt' not in merged
    assert evidence['sqlite_snapshot'].captures['readonly_observer_receipt'] != \
           evidence['subprocess_audit'].captures['readonly_observer_receipt']


def test_048_mutated_measurement_is_denied_before_merge():
    from types import SimpleNamespace
    signer=Ed25519PrivateKey.generate()
    a=_signed_snapshot(signer,source='sqlite_snapshot',measured={'value':1})
    b=_signed_snapshot(signer,source='subprocess_audit',measured={'different':2})
    evidence={'sqlite_snapshot':SimpleNamespace(captures=a),
              'subprocess_audit':SimpleNamespace(captures=b)}
    kw={'observer_key':signer.public_key(),'observer_id':'independent-test-observer',
        'run_id':'synthetic-run','git_sha':'a'*40,'command_digest':'b'*64}
    assert verify_readonly_observer_measurements(evidence,**kw)
    b['different']=99
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        verify_readonly_observer_measurements(evidence,**kw)


@pytest.mark.parametrize('mutation',[ 'missing_bytes','bad_sha','not_hex_sha',
    'bad_encoding','changed_target','wrong_uid','wrong_gid','wrong_errno',
    'missing_syscall','wrong_namespace','wrong_deployment','missing_time',
    'changed_nonce','changed_boot','changed_attester','unknown_broker'])
def test_049_primary_os_probe_artifact_negative_mutations(mutation):
    p,q,r,key=signed_case()
    iface=r['signer_deployment']['signing_interfaces'][0]
    artifact=iface['os_probe_artifact']
    data=__import__('json').loads(base64.b64decode(artifact['os_probe_bytes_b64']))
    if mutation=='missing_bytes': artifact.clear()
    elif mutation=='bad_sha': iface['os_probe_evidence_sha256']='0'*64
    elif mutation=='not_hex_sha': iface['os_probe_evidence_sha256']='z'*64
    elif mutation=='bad_encoding': artifact['os_probe_bytes_b64']='%^'
    else:
        if mutation=='changed_target': data['target']='/wrong/signing/socket'
        elif mutation=='wrong_uid': data['syscall_attempts'][0]['uid']=0
        elif mutation=='wrong_gid': data['syscall_attempts'][0]['gid']=0
        elif mutation=='wrong_errno': data['syscall_attempts'][0]['errno']='ALLOW'
        elif mutation=='missing_syscall': data['syscall_attempts'].pop()
        elif mutation=='wrong_namespace': data['syscall_attempts'][0]['namespace_id']='wrong-ns'
        elif mutation=='wrong_deployment': data['deployment_sha256']='0'*64
        elif mutation=='missing_time': data['syscall_attempts'][0]['timestamp_monotonic_ns']=0
        elif mutation=='changed_nonce': data['nonce']='replayed-nonce'
        elif mutation=='changed_boot': data['boot_id']='another-boot'
        elif mutation=='changed_attester': data['attester_id']='collector-itself'
        elif mutation=='unknown_broker': r['signer_deployment']['unaudited_signing_brokers']=1
        raw=_canon(data)
        iface['os_probe_artifact']={'os_probe_bytes_b64':base64.b64encode(raw).decode()}
        iface['os_probe_evidence_sha256']=_sha(raw)
    sig=key.sign(_canon(r)).hex()  # re-sign: probe validation must fail EVEN WITH valid signature
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        verify_oqa_receipt({'receipt':r,'signature':sig},p,q,attester_key=key.public_key())


def test_049_readonly_observer_probe_bytes_are_independently_hashed():
    p,q,r,key=signed_case()
    ob=r['readonly_observer_deployment']
    for keyname,value in (('os_probe_evidence_sha256','f'*64),
                          ('os_probe_artifact',{'os_probe_bytes_b64':'QQ==' }),
                          ('write_probe_bytes_before_sha256','f'*63+'?')):
        changed=copy.deepcopy(r)
        changed['readonly_observer_deployment'][keyname]=value
        with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
            verify_oqa_receipt({'receipt':changed,'signature':key.sign(_canon(changed)).hex()},p,q,
                               attester_key=key.public_key())
