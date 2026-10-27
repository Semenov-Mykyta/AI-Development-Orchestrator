"""RED-first regressions for FOURTH-D5-023..027 (test-contract scope only)."""
import hashlib
import os
from pathlib import Path
import pytest
from p01_probe import (ProbeError, verify_sut_proc_identity,
    verify_complete_git_history, verify_synthetic_object_bytes,
    _load_pinned_collector, verify_immutable_sut_checkout)


def status(uid='65534 65534 65534 65534',gid='65534 65534 65534 65534',caps='0'):
    return f'Uid:\t{uid}\nGid:\t{gid}\nGroups:\t\nCapEff:\t{caps}\nCapPrm:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n'


def test_fourth_023_reject_real_effective_uid_mismatch():
    with pytest.raises(ProbeError):
        verify_sut_proc_identity(status(uid='65534 0 0 0'),sut_uid=65534,sut_gid=65534,runner_uid=0)


def test_fourth_023_reject_capability_and_root_group():
    with pytest.raises(ProbeError):
        verify_sut_proc_identity(status(caps='1'),sut_uid=65534,sut_gid=65534,runner_uid=0)
    with pytest.raises(ProbeError):
        verify_sut_proc_identity(status().replace('Groups:\t','Groups:\t0'),sut_uid=65534,sut_gid=65534,runner_uid=0)


def test_fourth_023_allow_clean_isolated_identity():
    assert verify_sut_proc_identity(status(),sut_uid=65534,sut_gid=65534,runner_uid=0)


def test_fourth_024_reject_collector_writable_by_sut(tmp_path):
    file=tmp_path/'collector.py';file.write_text('def collect(**kw): return {}\n');file.chmod(0o600)
    with pytest.raises(ProbeError):
        _load_pinned_collector(file,hashlib.sha256(file.read_bytes()).hexdigest(),tmp_path/'sut',sut_uid=os.getuid())


def test_fourth_025_reject_dirty_checkout_even_if_head_stays_same(tmp_path):
    import subprocess
    repo=tmp_path/'repo';repo.mkdir(); subprocess.run(['git','init','-q',str(repo)],check=True)
    subprocess.run(['git','-C',str(repo),'config','user.email','synthetic@example.invalid'],check=True)
    subprocess.run(['git','-C',str(repo),'config','user.name','Synthetic'],check=True)
    tracked=repo/'bin.py';tracked.write_text('print(1)\n')
    subprocess.run(['git','-C',str(repo),'add','.'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','-qm','synthetic'],check=True)
    sha=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    executable=Path('/bin/echo').resolve()
    digest=hashlib.sha256(executable.read_bytes()).hexdigest()
    assert verify_immutable_sut_checkout(repo,sha,[str(executable)],digest,
        approved_components_sha256={str(executable):digest}, approved_launch_mode='direct_elf')
    tracked.write_text('print(2)\n')
    with pytest.raises(ProbeError):
        verify_immutable_sut_checkout(repo,sha,[str(executable)],digest,
            approved_components_sha256={str(executable):digest}, approved_launch_mode='direct_elf')


def test_fourth_026_reject_tip_only_scan_with_hidden_parent(tmp_path):
    import subprocess
    repo=tmp_path/'git';repo.mkdir()
    subprocess.run(['git','init','-q',str(repo)],check=True)
    for k,v in [('user.email','fixture@example.invalid'),('user.name','Fixture')]:
        subprocess.run(['git','-C',str(repo),'config',k,v],check=True)
    data=repo/'a';data.write_text('parent')
    subprocess.run(['git','-C',str(repo),'add','.'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','-qm','first'],check=True)
    parent=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    data.write_text('tip');subprocess.run(['git','-C',str(repo),'commit','-qam','second'],check=True)
    tip=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    ref=subprocess.check_output(['git','-C',str(repo),'symbolic-ref','HEAD'],text=True).strip()
    refs={ref:tip}
    with pytest.raises(ProbeError):
        verify_complete_git_history(refs,refs,verified_remote=True,
            reachable_commits={ref:[tip,parent]},scanned_commits=[tip],reachable_verified=True,
            trusted_remote_repo=repo, trusted_remote_url=repo.as_uri())
    assert verify_complete_git_history(refs,refs,verified_remote=True,
            reachable_commits={ref:[tip,parent]},scanned_commits=[tip,parent],reachable_verified=True,
            trusted_remote_repo=repo, trusted_remote_url=repo.as_uri())


def test_fourth_027_reject_decorative_digest():
    payload=b'fixture'*3
    spec={'seed_utf8':'fixture','size_bytes':len(payload),'sha256':'a'*64}
    with pytest.raises(ProbeError):
        verify_synthetic_object_bytes(spec,payload)
    spec['sha256']=hashlib.sha256(payload).hexdigest()
    assert verify_synthetic_object_bytes(spec,payload)
