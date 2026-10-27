"""SEVENTH-D5-037/038: reproduction-first, strictly synthetic contract tests.

These are NOT P01 acceptance evidence or owner inspection.
"""
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from p01_probe import (ProbeError, materialize_synthetic_objects,
                       verify_immutable_sut_checkout, require_sut_synthetic_evidence_access)


def _repo(tmp_path):
    repo=tmp_path/'repo'
    repo.mkdir()
    subprocess.run(['git','init','-q',str(repo)],check=True)
    subprocess.run(['git','-C',str(repo),'config','user.email','p01-test@example.invalid'],check=True)
    subprocess.run(['git','-C',str(repo),'config','user.name','P01 Test'],check=True)
    (repo/'tracked.txt').write_text('trusted fixture',encoding='utf8')
    subprocess.run(['git','-C',str(repo),'add','tracked.txt'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','-qm','synthetic fixture'],check=True)
    sha=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    return repo,sha


def test_seventh_037_env_python_wrapper_rejected_even_with_pinned_env_binary(tmp_path):
    repo,sha=_repo(tmp_path)
    env_binary=Path('/usr/bin/env')
    digest=hashlib.sha256(env_binary.read_bytes()).hexdigest()
    (tmp_path/'payload.py').write_text('print("unsigned")\n',encoding='utf8')
    # The script exists only in the SUT workspace, never in signed components.
    with pytest.raises(ProbeError,match='wrapper|interpreter|executable'):
        verify_immutable_sut_checkout(repo,sha,[str(env_binary),'python3','payload.py'],digest,
            approved_components_sha256={str(env_binary.resolve()):digest})


def test_seventh_037_env_absolute_unpinned_payload_rejected(tmp_path):
    repo,sha=_repo(tmp_path)
    env_binary=Path('/usr/bin/env')
    digest=hashlib.sha256(env_binary.read_bytes()).hexdigest()
    payload=tmp_path/'outside.py'
    payload.write_text('print("untrusted")\n')
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(env_binary),'python3',str(payload)],digest,
            approved_components_sha256={str(env_binary.resolve()):digest})


def test_seventh_037_approved_direct_binary_without_wrapper_still_allowed(tmp_path):
    repo,sha=_repo(tmp_path)
    binary=Path('/bin/echo').resolve()
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    # Direct signed executable, no interpreter flags or unsigned script.
    assert verify_immutable_sut_checkout(repo,sha,[str(binary)],digest,
            approved_components_sha256={str(binary):digest})


def _f(seed='evidence-data-01',size=99):
    seed_bytes=seed.encode('utf8')
    raw=(seed_bytes*(size//len(seed_bytes))+seed_bytes[:size%len(seed_bytes)])
    return {'protected_evidence_files':[{'path':'evidence/protected.bin','size_bytes':size,
        'sha256':hashlib.sha256(raw).hexdigest(),
        'generator':{'algorithm':'repeat_utf8_seed_v1','seed_utf8':seed,'size_bytes':size}}]}


def _as_sut_operation(workspace,uid=65534,gid=65534,operation='read'):
    script='''import pathlib,sys\np=pathlib.Path(sys.argv[1]);op=sys.argv[2]\ntry:\n p.read_bytes()\n if op=="delete": p.unlink()\nexcept OSError as e:\n print("DENIED",e.errno);sys.exit(9)\nprint("ALLOWED")\n'''
    return subprocess.run([sys.executable,'-c',script,str(workspace/'evidence/protected.bin'),operation],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5,
        user=uid,group=gid,extra_groups=[],env={'PATH':'/usr/bin:/bin'})


@pytest.fixture
def sut_tree():
    # /tmp is traversable for isolated uid=65534; pytest's private temp parent
    # deliberately is not, and must never be chmod'd to fabricate this result.
    with tempfile.TemporaryDirectory(prefix='aio-p01-seventh-',dir='/tmp') as name:
        root=Path(name)
        root.chmod(0o711)
        yield root


@pytest.mark.skipif(os.geteuid()!=0,reason='isolated synthetic UID test needs root; never escalate in production')
def test_seventh_038_evidence_is_sut_readable_and_evictable_not_root_owned(sut_tree):
    tmp_path=sut_tree
    # Separate runner identity (root) and SUT test identity (nobody).
    # The SUT owns only the disposable workspace, NEVER runner evidence or keys.
    tmp_path.chmod(0o711)
    workspace=tmp_path/'sut_workspace'
    workspace.mkdir(mode=0o700)
    os.chown(workspace,65534,65534)
    (tmp_path/'trusted_runner_evidence').mkdir(mode=0o700)
    runner_secret=tmp_path/'trusted_runner_evidence'/'witness.json'
    runner_secret.write_text('test-only, never a credential')
    runner_secret.chmod(0o600)
    created=materialize_synthetic_objects(_f(),workspace,sut_uid=65534,sut_gid=65534)
    assert len(created)==1
    item=created[0]
    assert item.stat().st_uid==65534
    assert item.parent.stat().st_uid==65534
    require_sut_synthetic_evidence_access(created,sut_uid=65534,sut_gid=65534)
    assert _as_sut_operation(workspace,operation='read').returncode==0
    # Positive lawful eviction must actually be possible for the SUT.
    assert _as_sut_operation(workspace,operation='delete').returncode==0
    assert not item.exists()
    # Trusted witness is strictly outside SUT workspace; independent evidence survives.
    assert runner_secret.read_text()=='test-only, never a credential'


@pytest.mark.skipif(os.geteuid()!=0,reason='isolated synthetic UID test needs root; never escalate in production')
def test_seventh_038_unmodified_runner_owned_evidence_does_not_fake_policy_pass(sut_tree):
    tmp_path=sut_tree
    tmp_path.chmod(0o711)
    workspace=tmp_path/'sut_workspace';workspace.mkdir(mode=0o700)
    os.chown(workspace,65534,65534)
    # Invalid setup: OS blocks read/deletion and should not be accepted as
    # evidence that SUT applied the normative retention policy.
    created=materialize_synthetic_objects(_f(),workspace)
    denial=_as_sut_operation(workspace,operation='delete')
    assert denial.returncode!=0 and created[0].exists()
    with pytest.raises(ProbeError,match='not SUT-readable'):
        require_sut_synthetic_evidence_access(created,sut_uid=65534,sut_gid=65534)
    # The assertion above documents the *bad* setup. The approved harness must
    # use sut_uid/sut_gid, as checked in test_seventh_038_evidence_*.
