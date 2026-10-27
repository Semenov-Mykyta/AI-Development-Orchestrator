"""RED-first reproduction: FIFTH-D5-028...032, no product/SUT or secrets."""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from p01_probe import (ProbeError, verify_sut_proc_identity,
                       verify_immutable_sut_checkout, _load_pinned_collector,
                       verify_complete_git_history)


def _os_status(groups):
    return ('Uid:\t65534 65534 65534 65534\nGid:\t65534 65534 65534 65534\n'
            f'Groups:\t{groups}\nCapEff:\t0\nCapPrm:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n')


def test_fifth_028_reject_any_extra_supplementary_group():
    for groups in ('27', '65534 27', '1000'):
        with pytest.raises(ProbeError):
            verify_sut_proc_identity(_os_status(groups),sut_uid=65534,sut_gid=65534,runner_uid=0)
    assert verify_sut_proc_identity(_os_status(''),sut_uid=65534,sut_gid=65534,runner_uid=0)


def _git_repo(path):
    path.mkdir()
    subprocess.run(['git','init','-q',str(path)],check=True)
    for key,val in [('user.email','synthetic@example.invalid'),('user.name','Synthetic')]:
        subprocess.run(['git','-C',str(path),'config',key,val],check=True)
    return path


def test_fifth_029_reject_changed_external_script_and_ignored_import(tmp_path):
    repo=_git_repo(tmp_path/'repo')
    (repo/'.gitignore').write_text('*.py\n')
    (repo/'committed.txt').write_text('commit source\n')
    subprocess.run(['git','-C',str(repo),'add','.gitignore','committed.txt'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','-qm','synthetic'],check=True)
    sha=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    script=tmp_path/'external_script.py';script.write_text('print(1)\n')
    python=Path(sys.executable).resolve();digest=hashlib.sha256(python.read_bytes()).hexdigest()
    components={str(python):digest,str(script):hashlib.sha256(script.read_bytes()).hexdigest()}
    assert verify_immutable_sut_checkout(repo,sha,[str(python),str(script)],digest,approved_components_sha256=components)
    script.write_text('print(2)\n')
    with pytest.raises(ProbeError):
        verify_immutable_sut_checkout(repo,sha,[str(python),str(script)],digest,approved_components_sha256=components)
    script.write_text('print(1)\n')
    (repo/'ignored_dependency.py').write_text('malicious=1\n')
    with pytest.raises(ProbeError):
        verify_immutable_sut_checkout(repo,sha,[str(python),str(script)],digest,approved_components_sha256=components)


def test_fifth_030_reject_collector_dependency_from_sut_writable_path(tmp_path, monkeypatch):
    # A root-controlled signed collector must NEVER import a sibling dependency in SUT space.
    collector=tmp_path/'collector.py';collector.write_text('import injected_dependency\ndef collect(**kw): return injected_dependency.collect(**kw)\n')
    untrusted=tmp_path/'sut';untrusted.mkdir()
    (untrusted/'injected_dependency.py').write_text('def collect(**kw): return {"wrong": {"accepted": True}}\n')
    monkeypatch.syspath_prepend(str(untrusted))
    with pytest.raises(ProbeError):
        _load_pinned_collector(collector,hashlib.sha256(collector.read_bytes()).hexdigest(),untrusted,sut_uid=65534)


def test_fifth_031_requires_runner_side_fixture_materialization(tmp_path):
    from p01_probe import materialize_synthetic_objects
    spec={'protected_evidence_files':[{'path':'evidence/protected.bin','size_bytes':137,
            'sha256':'0'*64,
            'generator':{'algorithm':'repeat_utf8_seed_v1','seed_utf8':'AIO!','size_bytes':137}}]}
    with pytest.raises(ProbeError):
        materialize_synthetic_objects(spec,tmp_path)
    spec['protected_evidence_files'][0]['sha256']=hashlib.sha256(b'AIO!'*34+b'A').hexdigest()
    # Bug in this test will be repaired if the expected synthetic bytes are wrong.
    out=materialize_synthetic_objects(spec,tmp_path)
    assert len(out)==1
    assert (tmp_path/'evidence'/'protected.bin').read_bytes()==b'AIO!'*34+b'A'


def test_fifth_032_reject_shallow_repository_even_if_reports_match(tmp_path):
    repo=_git_repo(tmp_path/'source')
    p=repo/'data';p.write_text('parent\n')
    subprocess.run(['git','-C',str(repo),'add','.'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','-qm','first'],check=True)
    p.write_text('tip\n');subprocess.run(['git','-C',str(repo),'commit','-qam','second'],check=True)
    shallow=tmp_path/'shallow';subprocess.run(['git','clone','-q','--depth','1',repo.as_uri(),str(shallow)],check=True)
    tip=subprocess.check_output(['git','-C',str(shallow),'rev-parse','HEAD'],text=True).strip()
    ref=subprocess.check_output(['git','-C',str(shallow),'symbolic-ref','HEAD'],text=True).strip()
    refs={ref:tip}
    with pytest.raises(ProbeError):
        verify_complete_git_history(refs,refs,verified_remote=True,
            reachable_commits={ref:[tip]},scanned_commits=[tip],reachable_verified=True,
            trusted_remote_repo=shallow, trusted_remote_url=repo.as_uri())


def test_fifth_031_chunk_boundary_preserves_exact_seed_stream(tmp_path):
    from p01_probe import materialize_synthetic_objects
    seed=b'eleven-byte'
    size=1048576+19
    actual=(seed*(size//len(seed))+seed[:size%len(seed)])
    target={'path':'synthetic.bin','size_bytes':size,'sha256':hashlib.sha256(actual).hexdigest(),
            'generator':{'algorithm':'repeat_utf8_seed_v1','seed_utf8':seed.decode(),'size_bytes':size}}
    materialize_synthetic_objects({'protected_evidence_files':[target]},tmp_path)
    assert (tmp_path/'synthetic.bin').read_bytes()==actual
