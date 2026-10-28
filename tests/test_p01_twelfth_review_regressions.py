"""TWELFTH-D5-046/047: synthetic external attestation contract tests only."""
import hashlib
import base64
import os
import socket
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from p01_oqa_attestation import (OQAttestationError, _canon, _sha, _protected_observer_socket,
                                validate_oqa_policy, verify_oqa_receipt,
                                verify_readonly_observer_measurements)


TEST_KERNEL_AUDIT_SIGNER=Ed25519PrivateKey.generate()  # test only, never production

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
        'oqa_kernel_audit_id':'synthetic-independent-kernel-sensor',
        'oqa_kernel_audit_public_key_path':'/root/trust/audit.pem',
        'oqa_kernel_audit_public_key_sha256':'f'*64,
        'oqa_kernel_audit_deployment_sha256':'1'*64,
        'sut_uid':65534,'sut_gid':65534,'collector_uid':65533,'collector_gid':65533}


def request(p):
    return {'schema':'aio.p01.oqa.deployment.challenge.v1','nonce':'test-nonce',
         'run_id':'run1','git_sha':'a'*40,'command_digest':'b'*64,
         'policy_sha256':_sha(_canon(p)),'attester_id':p['oqa_attester_id'],
         'monitor_id':p['kernel_monitor_id'],
         'monitor_public_key_sha256':p['kernel_monitor_public_key_sha256'],
         'sut_uid':p['sut_uid'],'sut_gid':p['sut_gid'],
         'collector_uid':p['collector_uid'],'collector_gid':p['collector_gid'],
         'required_sources':['filesystem_snapshot','sqlite_snapshot'],
         'boot_id':'synthetic-boot',
         'oqa_kernel_audit_id':p['oqa_kernel_audit_id'],
         'challenge_start_ns':1}


def signed_case():
    import time
    p=policy();q=request(p)
    r={'schema':'aio.p01.oqa.deployment.attested.v1',
       **{k:q[k] for k in ('nonce','run_id','git_sha','command_digest','policy_sha256',
                          'attester_id','monitor_id','monitor_public_key_sha256',
                          'collector_uid','collector_gid','sut_uid','sut_gid','required_sources','boot_id','oqa_kernel_audit_id')},
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
           'write_probe_bytes_before_sha256':_sha(b'synthetic untouched evidence'),
           'write_probe_bytes_after_sha256':_sha(b'synthetic untouched evidence'),
           'snapshot_scope_readonly_attested':True,'os_probe_evidence_sha256':'3'*64}}
    # Primary attester-observed syscall artifacts (synthetic signed test bytes).
    # They are not an actual OS attester or proof of kernel provenance.
    import time
    def recorded_artifact(kind,target,deployment,probes):
        stamp=time.monotonic_ns()
        doc={'schema':'aio.p01.oqa.os_probe.v1',
             **{k:q[k] for k in ('nonce','run_id','git_sha','command_digest',
                                    'policy_sha256','attester_id','boot_id','collector_uid','collector_gid','sut_uid','sut_gid')},
             'deployment_sha256':deployment,'target':target,'kind':kind,
             'provenance':'attester_os_syscalls','probe_origin':'independent_attester',
             'namespace_id':'synthetic-mount-ns','mac_profile':'synthetic-lsm-profile',
             'syscall_attempts':[{'role':role,
                 'uid':p['collector_uid'] if role=='collector' else p['sut_uid'],
                 'gid':p['collector_gid'] if role=='collector' else 65534,
                 'target':target,'operation':op,'errno':errno,
                 'timestamp_monotonic_ns':stamp,'namespace_id':'synthetic-mount-ns',
                 'mac_profile':'synthetic-lsm-profile'}
                 for role,op,errno in probes]}
        if kind=='readonly_observer':
            doc['write_denial_state']={'target_path':'/synthetic/observer-write-test.bin',
                 'before_b64':base64.b64encode(b'synthetic untouched evidence').decode(),
                 'after_b64':base64.b64encode(b'synthetic untouched evidence').decode()}
        raw=_canon(doc)
        return {'os_probe_bytes_b64':base64.b64encode(raw).decode()}, _sha(raw)
    iface=r['signer_deployment']['signing_interfaces'][0]
    iface['os_probe_artifact'],iface['os_probe_evidence_sha256']=recorded_artifact(
        'monitor_signing_interface',iface['target'],p['oqa_monitor_deployment_sha256'],
        [('collector','signing_request','EACCES'),('sut','signing_request','EACCES')])
    observer=r['readonly_observer_deployment']
    observer['os_probe_artifact'],observer['os_probe_evidence_sha256']=recorded_artifact(
        'readonly_observer',observer['observer_socket_path'],p['oqa_observer_deployment_sha256'],
        [('collector','rpc_read','ALLOW'),('collector','rpc_write','EACCES'),
         ('sut','rpc_write','EACCES')])
    r['issued_monotonic_ns']=time.monotonic_ns()  # AFTER primary OS event times
    events=[]
    for kind,target,artifact in (
       ('monitor_signing_interface',iface['target'],iface['os_probe_artifact']),
       ('readonly_observer',observer['observer_socket_path'],observer['os_probe_artifact'])):
        obj=__import__('json').loads(base64.b64decode(artifact['os_probe_bytes_b64']))
        for event in obj['syscall_attempts']:
            events.append({'kind':kind,'target':target,'role':event['role'],
                 'uid':event['uid'],'gid':event['gid'],'operation':event['operation'],
                 'errno':event['errno'],'timestamp_monotonic_ns':event['timestamp_monotonic_ns'],
                 'namespace_id':event['namespace_id'],'mac_profile':event['mac_profile']})
    audit_record={'schema':'aio.p01.oqa.kernel_audit.v1',
        'audit_id':p['oqa_kernel_audit_id'],
        'deployment_sha256':p['oqa_kernel_audit_deployment_sha256'],
        **{k:q[k] for k in ('nonce','run_id','git_sha','command_digest','policy_sha256','boot_id')},
        'event_digest_set_sha256':_sha(_canon(sorted([
            iface['os_probe_evidence_sha256'], observer['os_probe_evidence_sha256']]))),
        'source':'linux_audit_netlink_v1','origin':'kernel_syscall_events',
        'event_loss_count':0,'all_signing_endpoints_observed':True,
        'kernel_syscall_events':events,
        'discovered_signing_endpoints':[iface['target']],
        'independent_of_attester_collector_sut':True,
        'capture_started_ns':q['challenge_start_ns'],
        'capture_stopped_ns':r['issued_monotonic_ns']}
    r['__synthetic_kernel_audit_envelope']={
        'receipt':audit_record,'signature':TEST_KERNEL_AUDIT_SIGNER.sign(_canon(audit_record)).hex()}
    signer=Ed25519PrivateKey.generate()
    return p,q,r,signer


def synthetic_response(r, key):
    """Produce two independent TEST signatures, never runtime evidence."""
    payload={k:v for k,v in r.items() if k!='__synthetic_kernel_audit_envelope'}
    return {'receipt':payload,'signature':key.sign(_canon(payload)).hex(),
            'kernel_audit':r['__synthetic_kernel_audit_envelope']}


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
    valid=synthetic_response(r,key)
    assert verify_oqa_receipt(valid,p,q,attester_key=key.public_key(),
                                  kernel_audit_key=TEST_KERNEL_AUDIT_SIGNER.public_key())
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
        signed=synthetic_response(mutation,key)
        with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
            verify_oqa_receipt(signed,p,q,attester_key=key.public_key(),
                                  kernel_audit_key=TEST_KERNEL_AUDIT_SIGNER.public_key())


def test_046_replay_other_run_or_wrong_attester_key_rejected():
    p,q,r,key=signed_case()
    signed=synthetic_response(r,key)
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        verify_oqa_receipt(signed,p,{**q,'nonce':'new-nonce'},attester_key=key.public_key(),
                                  kernel_audit_key=TEST_KERNEL_AUDIT_SIGNER.public_key())
    with pytest.raises(OQAttestationError,match='NOT_CHECKED'):
        verify_oqa_receipt(signed,p,q,attester_key=Ed25519PrivateKey.generate().public_key(),
                           kernel_audit_key=TEST_KERNEL_AUDIT_SIGNER.public_key())


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
