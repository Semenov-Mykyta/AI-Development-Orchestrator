"""Eighth-review red-first executable-chain regression fixtures, no actual P01."""
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from p01_probe import ProbeError, verify_immutable_sut_checkout


def repo_at(tmp_path):
    repo = tmp_path / 'repo'
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    subprocess.run(['git', '-C', str(repo), 'config', 'user.email', 'oracle@example.invalid'], check=True)
    subprocess.run(['git', '-C', str(repo), 'config', 'user.name', 'Synthetic'], check=True)
    (repo / 'source.txt').write_text('approved', encoding='utf8')
    subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(repo), 'commit', '-qm', 'synthetic'], check=True)
    sha = subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'], text=True).strip()
    return repo, sha


def pinned(binary):
    binary = binary.resolve()
    return hashlib.sha256(binary.read_bytes()).hexdigest(), {str(binary): hashlib.sha256(binary.read_bytes()).hexdigest()}


@pytest.mark.parametrize('launcher,payload_name', [
    ('/usr/bin/dash', 'payload.sh'),
    ('/usr/bin/perl', 'payload.pl'),
])
def test_eighth_039_interpreters_cannot_run_unsigned_relative_scripts(tmp_path,launcher,payload_name):
    exe=Path(launcher)
    if not exe.is_file():
        pytest.skip('synthetic interpreter unavailable')
    repo,sha=repo_at(tmp_path)
    (tmp_path/payload_name).write_text('print("attacker")\n', encoding='utf8')
    digest, components=pinned(exe)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(exe),payload_name],digest,
                                      approved_components_sha256=components,approved_launch_mode='direct_elf')


def test_eighth_039_renamed_env_with_unsigned_payload_rejected(tmp_path):
    original=Path('/usr/bin/env')
    if not original.exists(): pytest.skip('env absent')
    repo,sha=repo_at(tmp_path)
    renamed=tmp_path/'trusted-executor'
    shutil.copy2(original,renamed)
    (tmp_path/'payload.py').write_text('print("unsigned")\n')
    digest,components=pinned(renamed)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(renamed),'python3','payload.py'],digest,
                                      approved_components_sha256=components,approved_launch_mode='direct_elf')


def test_eighth_039_approved_python_script_requires_explicit_signed_mode(tmp_path):
    repo,sha=repo_at(tmp_path)
    python=Path(sys.executable).resolve()
    script=tmp_path/'script.py';script.write_text('print("synthetic")\n')
    digest,components=pinned(python)
    components[str(script)]=hashlib.sha256(script.read_bytes()).hexdigest()
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(python),str(script)],digest,
                                      approved_components_sha256=components)
    assert verify_immutable_sut_checkout(repo,sha,[str(python),str(script)],digest,
                                       approved_components_sha256=components,
                                       approved_launch_mode='pinned_python_script')


def test_eighth_039_approved_direct_elf_without_other_commands_still_allowed(tmp_path):
    repo,sha=repo_at(tmp_path)
    binary=Path('/bin/echo').resolve()
    digest,components=pinned(binary)
    assert verify_immutable_sut_checkout(repo,sha,[str(binary)],digest,
                            approved_components_sha256=components,approved_launch_mode='direct_elf')
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(binary),'unsigned-command'],digest,
                            approved_components_sha256=components,approved_launch_mode='direct_elf')


def test_eighth_039_no_signed_policy_launch_mode_denied(tmp_path):
    from p01_probe import verify_signed_collector_policy,_canonical
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    owner=Ed25519PrivateKey.generate();pk=tmp_path/'owner.pem'
    pk.write_bytes(owner.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    collector=tmp_path/'collector.py';collector.write_text('def collect(**kw): return {}\n')
    fields={'schema':'aio.p01.owner_signed_collector_policy.v1','collector_sha256':hashlib.sha256(collector.read_bytes()).hexdigest(),
    'collector_path':str(collector),'witness_key_path':str(tmp_path/'key'),'git_sha':'a'*40,
    'sut_uid':65534,'sut_gid':65534,'runner_uid':0,'authorized_by':'trusted-owner','scope':'P01-D5',
    'sut_command_sha256':'a'*64,'sut_repo_path':str(tmp_path),'sut_executable_sha256':'b'*64,
    'sut_components_sha256':{'/bin/false':'b'*64},'git_scan_mirror_path':str(tmp_path),
    'git_test_remote_url':'file:///test-remote','synthetic_root_path':'/synthetic'}
    b=_canonical(fields)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_signed_collector_policy(b,owner.sign(b),pk,collector_file=collector,git_sha='a'*40)


def test_eighth_039_renamed_env_cannot_claim_python_launch_mode(tmp_path):
    env_path=Path('/usr/bin/env')
    if not env_path.is_file(): pytest.skip('env absent')
    repo,sha=repo_at(tmp_path)
    fake_python=tmp_path/'python3';shutil.copy2(env_path,fake_python)
    script=tmp_path/'pinned.py';script.write_text('print("pinned")\n')
    digest,components=pinned(fake_python)
    components[str(script)]=hashlib.sha256(script.read_bytes()).hexdigest()
    with pytest.raises(ProbeError, match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(fake_python),str(script)],digest,
            approved_components_sha256=components,approved_launch_mode='pinned_python_script')

def test_eighth_039_elf_mode_rejects_script_file_even_if_signed(tmp_path):
    repo,sha=repo_at(tmp_path)
    executable=Path('/bin/echo').resolve();digest,components=pinned(executable)
    script=tmp_path/'approved_script.sh';script.write_text('echo approved\n')
    components[str(script)]=hashlib.sha256(script.read_bytes()).hexdigest()
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(executable),str(script)],digest,
                                      approved_components_sha256=components,approved_launch_mode='direct_elf')
