"""TWELFTH-D5-046/047: synthetic external attestation contract tests only."""
import hashlib
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from p01_oqa_attestation import (OQAttestationError, _canon, _sha, _protected_observer_socket,
                                validate_oqa_policy, verify_oqa_receipt,
                                verify_readonly_observer_measurements)


def policy():
    return {'oqa_attester_id':'independent-oqa-inspector',
        'oqa_attester_public_key_path':'/root/trust/oqa.pem',
        'oqa_attester_public_key_sha256':'a'*64,
        'oqa_attester_socket_path':'/root/trust/oqa.sock',
        'oqa_monitor_deployment_sha256':'b'*64,
        'oqa_observer_deployment_sha256':'c'*64,
        'readonly_observer_id':'readonly-observer-1',
        'readonly_observer_public_key_path':'/root/trust/observer.pem',
        'readonly_observer_public_key_sha256':'d'*64,
        'readonly_observer_socket_path':'/root/trust/observer.sock',
        'readonly_observer_protocol':'aio.p01.readonly_snapshot.v1',
        'readonly_observer_sources':['filesystem_snapshot','sqlite_snapshot'],
        'kernel_monitor_public_key_sha256':'e'*64,'kernel_monitor_id':'monitor-1',
        'sut_uid':65534,'collector_uid':65533,'collector_gid':65533}


def request(p):
    return {'schema':'aio.p01.oqa.deployment.challenge.v1','nonce':'test-nonce',
         'run_id':'run1','git_sha':'a'*40,'command_digest':'b'*64,
         'policy_sha256':_sha(_canon(p)),'attester_id':p['oqa_attester_id'],
         'monitor_id':p['kernel_monitor_id'],
         'monitor_public_key_sha256':p['kernel_monitor_public_key_sha256'],
         'sut_uid':p['sut_uid'],'collector_uid':p['collector_uid'],
         'required_sources':['filesystem_snapshot','sqlite_snapshot'],
         'boot_id':'synthetic-boot','challenge_start_ns':1}


def signed_case():
    import time
    p=policy();q=request(p)
    r={'schema':'aio.p01.oqa.deployment.attested.v1',
       **{k:q[k] for k in ('nonce','run_id','git_sha','command_digest','policy_sha256',
                          'attester_id','monitor_id','monitor_public_key_sha256',
                          'collector_uid','sut_uid','required_sources','boot_id')},
       'issued_monotonic_ns':time.monotonic_ns(),
       'signer_deployment':{'deployment_sha256':p['oqa_monitor_deployment_sha256'],
           'monitor_id':'monitor-1','monitor_public_key_sha256':'e'*64,
           'signer_key_id':'actual-approved-signer','actual_key_storage_measured':True,
           'namespace_and_mac_policy_measured':True,
           'all_signing_interfaces_enumerated':True,
           'unaudited_signing_brokers':0,'fabricated_event_signing_rejected':True,
           'signing_interfaces':[{'target':'/root/monitor/actual-signer',
               'collector_access_errno':'EACCES','sut_access_errno':'EACCES',
               'signer_key_id':'actual-approved-signer','os_probe_evidence_sha256':'1'*64}]},
       'readonly_observer_deployment':{'deployment_sha256':p['oqa_observer_deployment_sha256'],
           'observer_id':p['readonly_observer_id'],
           'observer_public_key_sha256':p['readonly_observer_public_key_sha256'],
           'observer_socket_path':p['readonly_observer_socket_path'],
           'protocol':'aio.p01.readonly_snapshot.v1',
           'independently_measured_sources':q['required_sources'],
           'snapshot_source':'trusted_os_broker','sut_can_supply_measurements':False,
           'root_fallback':False,'collector_read_probe':'ALLOW',
           'collector_write_probe':'EACCES','sut_write_probe':'EACCES',
           'write_probe_bytes_before_sha256':'2'*64,'write_probe_bytes_after_sha256':'2'*64,
           'snapshot_scope_readonly_attested':True,'os_probe_evidence_sha256':'3'*64}}
    signer=Ed25519PrivateKey.generate()
    return p,q,r,signer


def test_046_047_signed_policy_must_pin_both_services():
    p=policy()
    assert validate_oqa_policy(p)
    for key in ('oqa_attester_socket_path','oqa_monitor_deployment_sha256',
                'readonly_observer_sources','readonly_observer_socket_path'):
        damaged=dict(p);damaged.pop(key)
        with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
            validate_oqa_policy(damaged)
    damaged=dict(p);damaged['readonly_observer_public_key_sha256']=p['kernel_monitor_public_key_sha256']
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        validate_oqa_policy(damaged)


def test_046_actual_signer_deployment_signature_and_all_interfaces_required():
    p,q,r,key=signed_case()
    valid={'receipt':r,'signature':key.sign(_canon(r)).hex()}
    assert verify_oqa_receipt(valid,p,q,attester_key=key.public_key())
    for path,value in [('signer_deployment.signing_interfaces',[]),
                       ('signer_deployment.unaudited_signing_brokers',1),
                       ('signer_deployment.actual_key_storage_measured',False),
                       ('signer_deployment.fabricated_event_signing_rejected',False),
                       ('readonly_observer_deployment.collector_write_probe','ALLOW'),
                       ('readonly_observer_deployment.root_fallback',True),
                       ('readonly_observer_deployment.snapshot_source','sut_json')]:
        import copy
        mutation=copy.deepcopy(r);section,name=path.split('.')
        mutation[section][name]=value
        signed={'receipt':mutation,'signature':key.sign(_canon(mutation)).hex()}
        with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
            verify_oqa_receipt(signed,p,q,attester_key=key.public_key())


def test_046_replay_other_run_or_wrong_attester_key_rejected():
    p,q,r,key=signed_case()
    signed={'receipt':r,'signature':key.sign(_canon(r)).hex()}
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        verify_oqa_receipt(signed,p,{**q,'nonce':'new-nonce'},attester_key=key.public_key())
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        verify_oqa_receipt(signed,p,q,attester_key=Ed25519PrivateKey.generate().public_key())


def test_047_only_attested_readonly_observer_measurements_accepted():
    signer=Ed25519PrivateKey.generate()
    measured={'protected_evidence_removed':0}
    receipt={'schema':'aio.p01.observer.snapshot.v1','observer_id':'readonly-observer-1',
             'source':'filesystem_snapshot','run_id':'run1','git_sha':'a'*40,
             'command_digest':'b'*64,'measurement_sha256':_sha(_canon(measured)),
             'readonly':True,'origin':'trusted_os_broker'}
    signed={'receipt':receipt,'signature':signer.sign(_canon(receipt)).hex()}
    proof=SimpleNamespace(captures={**measured,'readonly_observer_receipt':signed})
    expected={'filesystem_snapshot':proof}
    kw={'observer_key':signer.public_key(),'observer_id':'readonly-observer-1',
        'run_id':'run1','git_sha':'a'*40,'command_digest':'b'*64}
    assert verify_readonly_observer_measurements(expected,**kw)
    for bad in ({'filesystem_snapshot':SimpleNamespace(captures=measured)},
                {'filesystem_snapshot':SimpleNamespace(captures={**measured,
                  'readonly_observer_receipt':{'receipt':receipt,'signature':'00'*64}})},
                {'filesystem_snapshot':SimpleNamespace(captures={**measured,
                  'protected_evidence_removed':1,'readonly_observer_receipt':signed})}):
        with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
            verify_readonly_observer_measurements(bad,**kw)


def test_047_socket_requires_collector_only_group_and_rejects_world_writes():
    if os.geteuid()!=0:pytest.skip('synthetic isolated root test only')
    import tempfile
    with tempfile.TemporaryDirectory(dir='/root',prefix='aio-oqa-') as folder:
        root=Path(folder);root.chmod(0o711)
        p=root/'observer.sock';s=socket.socket(socket.AF_UNIX)
        s.bind(str(p));os.chown(p,0,65533);p.chmod(0o660)
        try:
            assert _protected_observer_socket(p,65533) is None
            p.chmod(0o666)
            with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
                _protected_observer_socket(p,65533)
        finally:s.close()


def test_047_no_self_report_substitute_for_independent_observer():
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        verify_readonly_observer_measurements({'filesystem_snapshot':SimpleNamespace(captures={
            'allow':True,'reported_by_sut':True})},observer_key=Ed25519PrivateKey.generate().public_key(),
            observer_id='readonly-observer-1',run_id='run1',git_sha='a'*40,
            command_digest='b'*64)
