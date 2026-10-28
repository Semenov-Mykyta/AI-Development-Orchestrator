"""Eleventh independent-review regression tests for D5 contract, synthetic only.

No production credentials, kernel monitor deployment, or P01 acceptance PASS.
"""
import hashlib
import inspect
import os
import socket
import stat
import tempfile
from pathlib import Path

import pytest

from p01_probe import (ProbeError, _execute_collector_isolated,
                       require_monitor_signer_isolation)


def test_045_collector_must_refuse_missing_or_privileged_role():
    payload=b'def collect(**kwargs): return {"filesystem_snapshot":{"ok":True}}\n'
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        _execute_collector_isolated(payload,{}, {}, ['filesystem_snapshot'],
                                    collector_uid=0,collector_gid=0)


def test_045_collector_drops_root_and_inherits_no_capabilities():
    if os.geteuid()!=0: pytest.skip('isolated UID/GID test requires test-only root')
    payload=b'''\
from pathlib import Path
import os
def collect(*,synthetic_input,run,required_sources):
    lines=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    return {'filesystem_snapshot':{'uid':os.geteuid(),'gid':os.getegid(),
       'groups':lines['Groups'].strip(),'no_new_privs':lines['NoNewPrivs'].strip(),
       'cap_effective':int(lines['CapEff'],16),'cap_permitted':int(lines['CapPrm'],16),
       'cap_ambient':int(lines['CapAmb'],16)}}
'''
    data=_execute_collector_isolated(payload,{'operation':'synthetic'}, {},
                                      ['filesystem_snapshot'],
                                      collector_uid=65533,collector_gid=65533)
    assert data['filesystem_snapshot']=={
        'uid':65533,'gid':65533,'groups':'','no_new_privs':'1',
        'cap_effective':0,'cap_permitted':0,'cap_ambient':0}


def _root_only_synthetic_guard():
    if os.geteuid()!=0: pytest.skip('synthetic signer guard test requires root')
    if not Path('/root').is_dir(): pytest.skip('no disposable root-controlled test directory')
    return tempfile.TemporaryDirectory(prefix='aio-d5-045-',dir='/root')


def test_045_real_negative_probes_separate_collector_and_sut():
    with _root_only_synthetic_guard() as folder:
        root=Path(folder)
        root.chmod(0o711)
        sentinel=root/'synthetic-guard'
        sentinel.write_bytes(b'NOT A REAL MONITOR PRIVATE KEY')
        sentinel.chmod(0o600)
        endpoint=root/'monitor-control.sock'
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(str(endpoint))
        endpoint.chmod(0o600)
        server.listen(1)
        try:
            assert require_monitor_signer_isolation(
                sentinel,endpoint,sut_uid=65534,sut_gid=65534,
                collector_uid=65533,collector_gid=65533)
        finally:
            server.close()


def test_045_writable_signer_guard_must_not_qualify():
    with _root_only_synthetic_guard() as folder:
        root=Path(folder);root.chmod(0o711)
        sentinel=root/'synthetic-guard';sentinel.write_bytes(b'test')
        sentinel.chmod(0o644)  # unsafe shared signing-key protection
        endpoint=root/'monitor-control.sock'
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(str(endpoint));endpoint.chmod(0o600)
        try:
            with pytest.raises(ProbeError,match='NOT_CHECKED'):
                require_monitor_signer_isolation(
                    sentinel,endpoint,sut_uid=65534,sut_gid=65534,
                    collector_uid=65533,collector_gid=65533)
        finally:
            server.close()


def test_045_same_collector_and_sut_uid_denied():
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        require_monitor_signer_isolation(
            Path('/root/synthetic-only-guard'),Path('/root/no-socket'),
            sut_uid=65534,sut_gid=65534,collector_uid=65534,collector_gid=65533)


def test_045_owner_signed_policy_requires_separate_roles_and_guard():
    from p01_probe import verify_signed_collector_policy, _canonical
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        key=Ed25519PrivateKey.generate()
        pub=root/'owner.pem'
        pub.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        collector=root/'collector.py';collector.write_text('def collect(**kw): return {}\n')
        policy={'schema':'aio.p01.owner_signed_collector_policy.v1',
                'collector_sha256':hashlib.sha256(collector.read_bytes()).hexdigest(),
                'collector_path':str(collector),'witness_key_path':str(root/'key'),
                'git_sha':'a'*40,'sut_uid':65534,'sut_gid':65534,'runner_uid':0,
                'collector_uid':65533,'collector_gid':65533,
                'authorized_by':'synthetic-owner','scope':'P01-D5',
                'sut_command_sha256':'a'*64,'sut_repo_path':'/synthetic/repo',
                'sut_executable_sha256':'b'*64,'sut_launch_mode':'direct_elf',
                'sut_components_sha256':{'/bin/true':'b'*64},
                'git_scan_mirror_path':'/synthetic/mirror',
                'git_test_remote_url':'file:///synthetic/test-remote',
                'synthetic_root_path':'/synthetic','kernel_monitor_id':'synthetic-monitor',
                'kernel_monitor_public_key_path':'/synthetic/monitor.pub',
                'kernel_monitor_public_key_sha256':'c'*64,
                'kernel_monitor_socket_path':'/synthetic/monitor.sock',
                'monitor_key_isolation_probe_path':'/synthetic/key-guard'}
        raw=_canonical(policy)
        assert verify_signed_collector_policy(
            raw,key.sign(raw),pub,collector_file=collector,git_sha='a'*40)['collector_uid']==65533
        for bad in ({**policy,'collector_uid':0},
                    {**policy,'collector_uid':65534},
                    {**policy,'collector_gid':65534},
                    {k:v for k,v in policy.items() if k!='monitor_key_isolation_probe_path'}):
            raw=_canonical(bad)
            with pytest.raises(ProbeError,match='NOT_CHECKED'):
                verify_signed_collector_policy(
                    raw,key.sign(raw),pub,collector_file=collector,git_sha='a'*40)


def test_045_acceptance_makes_negative_probe_before_popen_and_passes_roles():
    from test_p01_acceptance import approved_test_subprocess, test_p01_normative_acceptance
    a=inspect.getsource(approved_test_subprocess.__wrapped__)
    run=inspect.getsource(test_p01_normative_acceptance)
    assert 'require_monitor_signer_isolation(' in a
    assert a.index('require_monitor_signer_isolation(')<a.index('return argv,')
    assert 'collector_uid=collector_uid,collector_gid=collector_gid' in run
    assert 'arm_monitor_session(' in run
    assert 'verify_execution_closure(' in run
