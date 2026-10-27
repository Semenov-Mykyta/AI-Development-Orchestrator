"""Reproduction-first regressions SIXTH-D5-033...036, synthetic only."""
import hashlib
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest
from p01_probe import ProbeError, verify_immutable_sut_checkout, materialize_synthetic_objects


def _repo(tmp_path):
    repo=tmp_path/'repo';repo.mkdir()
    subprocess.run(['git','init','-q',str(repo)],check=True)
    subprocess.run(['git','-C',str(repo),'config','user.email','synthetic@example.invalid'],check=True)
    subprocess.run(['git','-C',str(repo),'config','user.name','Synthetic'],check=True)
    (repo/'test.txt').write_text('test')
    subprocess.run(['git','-C',str(repo),'add','.'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','-qm','synthetic'],check=True)
    sha=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    return repo,sha


def test_sixth_034_rejects_flag_before_unapproved_relative_script(tmp_path):
    repo,sha=_repo(tmp_path)
    py=Path(sys.executable).resolve()
    digest=hashlib.sha256(py.read_bytes()).hexdigest()
    (repo/'payload.py').write_text('print("unapproved")')
    subprocess.run(['git','-C',str(repo),'add','payload.py'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','-qm','pinned fixture'],check=True)
    sha=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    # Previous guard checked argv[1] = '-B' and never checked argv[2].
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(py),'-B','payload.py'],digest,
                                      approved_components_sha256={str(py):digest},approved_launch_mode='pinned_python_script')


def test_sixth_033_approved_remote_reaches_run_builder_without_unbound_policy(tmp_path):
    # A unit-level check of runner metadata construction; no P01 acceptance PASS.
    from test_p01_acceptance import build_p01_test_run
    from p01_probe import TestRun
    workspace=tmp_path/'workspace';workspace.mkdir()
    run=build_p01_test_run(pids=[100],codes=[0],start_ticks=4,argv=['/synthetic/runner'],
         raw={'operation':'test'},workspace=workspace,git_sha='a'*40,collector_sha='b'*64,
         trusted_git_mirror=tmp_path/'test-mirror',trusted_remote_url='file:///approved/test-remote')
    assert isinstance(run,TestRun)
    assert run.trusted_remote_url=='file:///approved/test-remote'
    assert run.process_pids==(100,)


def test_sixth_035_cached_dependency_must_not_influence_collector(tmp_path,monkeypatch):
    # Run a pinned stdlib-only collector in a fresh -I -S interpreter, not current sys.modules.
    from p01_probe import _execute_collector_isolated
    payload=b'import injected_cached_module\ndef collect(**kw): return injected_cached_module.collect(**kw)\n'
    attacker=types.ModuleType('injected_cached_module')
    attacker.collect=lambda **kw: {'filesystem_snapshot':{'allowed':True}}
    monkeypatch.setitem(sys.modules,'injected_cached_module',attacker)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        _execute_collector_isolated(payload, {'operation':'synthetic'}, {'workspace':str(tmp_path)}, ['filesystem_snapshot'])


def test_sixth_035_clean_interpreter_can_run_approved_stdlib_collector(tmp_path):
    from p01_probe import _execute_collector_isolated
    (tmp_path/'measured.txt').write_text('real')
    payload=b'from pathlib import Path\ndef collect(*,synthetic_input,run,required_sources):\n return {"filesystem_snapshot":{"measured":Path(run.workspace,"measured.txt").read_text()}}\n'
    result=_execute_collector_isolated(payload,{'operation':'synthetic'}, {'workspace':str(tmp_path)}, ['filesystem_snapshot'])
    assert result=={'filesystem_snapshot':{'measured':'real'}}


def _fixture(seed='z', size=11, digest=None):
    expected=(seed.encode()*(size//len(seed.encode()))+seed.encode()[:size%len(seed.encode())])
    return {'protected_evidence_files':[{'path':'synthetic/record.bin','size_bytes':size,
        'sha256':digest or hashlib.sha256(expected).hexdigest(),
        'generator':{'algorithm':'repeat_utf8_seed_v1','seed_utf8':seed,'size_bytes':size}}]}


def test_sixth_036_wrong_digest_leaves_no_file(tmp_path):
    with pytest.raises(ProbeError):
        materialize_synthetic_objects(_fixture(digest='0'*64),tmp_path)
    assert not (tmp_path/'synthetic/record.bin').exists()


def test_sixth_036_second_file_failure_rolls_back_prior_file(tmp_path):
    fixtures=_fixture()
    fixtures['protected_evidence_files'].append({'path':'synthetic/second.bin','size_bytes':1,
        'sha256':'0'*64,'generator':{'algorithm':'repeat_utf8_seed_v1','seed_utf8':'x','size_bytes':1}})
    with pytest.raises(ProbeError):
        materialize_synthetic_objects(fixtures,tmp_path)
    assert not (tmp_path/'synthetic/record.bin').exists()
    assert not (tmp_path/'synthetic/second.bin').exists()


def test_sixth_036_error_during_second_read_cleans_file(tmp_path,monkeypatch):
    real_sha=hashlib.sha256
    calls=[0]
    def corrupted_on_remeasure(*args, **kwargs):
        calls[0]+=1
        obj=real_sha(*args,**kwargs)
        if calls[0]==2:
            class Corrupt:
                def update(self,data): obj.update(data)
                def hexdigest(self): return 'f'*64
            return Corrupt()
        return obj
    monkeypatch.setattr('p01_probe.hashlib.sha256',corrupted_on_remeasure)
    with pytest.raises(ProbeError):
        materialize_synthetic_objects(_fixture(),tmp_path)
    assert not (tmp_path/'synthetic/record.bin').exists()


def test_sixth_036_partial_write_fsync_error_rolls_back(tmp_path,monkeypatch):
    # An OS failure after a partial write must not leave reusable synthetic bytes.
    def disk_fault(_fd):
        raise OSError('synthetic disk exhausted before durable bytes')
    monkeypatch.setattr(os,'fsync',disk_fault)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        materialize_synthetic_objects(_fixture(),tmp_path)
    assert not (tmp_path/'synthetic/record.bin').exists()
