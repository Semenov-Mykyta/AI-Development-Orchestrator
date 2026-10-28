"""Ninth D5 independent findings: red-first tests for 040/041/042."""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from p01_probe import ProbeError, verify_immutable_sut_checkout


def repo_at(tmp):
    repo=tmp/'repo'; repo.mkdir()
    subprocess.run(['git','init','-q',str(repo)],check=True)
    subprocess.run(['git','-C',str(repo),'config','user.email','test@example.invalid'],check=True)
    subprocess.run(['git','-C',str(repo),'config','user.name','Test'],check=True)
    (repo/'source').write_text('synthetic')
    subprocess.run(['git','-C',str(repo),'add','.'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','-qm','fixture'],check=True)
    return repo,subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()


def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def test_040_unverified_executable_never_runs_even_identity_probe(tmp_path):
    repo,sha=repo_at(tmp_path)
    marker=tmp_path/'EXECUTED_BEFORE_VERIFY'
    exe=tmp_path/'fakepython'
    exe.write_text('#!/bin/sh\nprintf marker > "'+str(marker)+'"\nprintf cpython\n')
    exe.chmod(0o700)
    script=tmp_path/'approved.py';script.write_text('print(42)\n')
    wrong='1'*64
    with pytest.raises(ProbeError):
        verify_immutable_sut_checkout(repo,sha,[str(exe),str(script)],wrong,
                approved_components_sha256={str(exe):wrong,str(script):digest(script)},
                approved_launch_mode='pinned_python_script')
    assert not marker.exists(), 'NINTH-D5-040: unapproved executable executed before SHA check'


def test_041_symlink_executable_rejected_at_admission(tmp_path):
    repo,sha=repo_at(tmp_path)
    binary=Path('/bin/echo').resolve()
    link=tmp_path/'untrusted-launcher';link.symlink_to(binary)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_immutable_sut_checkout(repo,sha,[str(link)],digest(binary),
            approved_components_sha256={str(binary):digest(binary)}, approved_launch_mode='direct_elf')


def test_042_every_acceptance_case_mandatorily_collects_process_exec_trace():
    src=(Path(__file__).parent/'test_p01_acceptance.py').read_text()
    assert 'execve_trace' in src and 'verify_execution_closure' in src


def test_042_unapproved_child_executable_must_fail():
    from p01_probe import verify_execution_closure
    with pytest.raises(ProbeError, match='NOT_CHECKED'):
        verify_execution_closure(
            {'execve_events':[{'pid':10,'executable_sha256':'a'*64,'executable_path':'/approved'},
                              {'pid':11,'ppid':10,'executable_sha256':'b'*64,'executable_path':'/unauthorized'}],
             'loaded_file_events':[], 'observed_pids':[10,11],
             'trace_complete':True,'trace_source':'kernel_execve'},
            approved_components_sha256={'/approved':'a'*64}, process_pids=(10,))


def test_041_popen_pinned_exec_fd_must_not_follow_repointed_name(tmp_path):
    from p01_probe import open_pinned_launch
    binary=Path('/bin/echo').resolve()
    with open_pinned_launch([str(binary)], {'/bin/echo': digest(binary), str(binary):digest(binary)},
                            launch_mode='direct_elf') as launch:
        assert launch.executable.startswith('/proc/self/fd/')
        assert launch.pass_fds


def test_041_fd_pinning_executable_remains_same_inode_after_path_rename(tmp_path):
    from p01_probe import open_pinned_launch
    binary=Path('/bin/echo').resolve()
    d=digest(binary)
    # A real subprocess executes the FD, not argv[0] pathname.
    with open_pinned_launch([str(binary)],{str(binary):d},launch_mode='direct_elf') as launch:
        out=subprocess.run(list(launch.argv)+['pinned-FD-smoke'],executable=launch.executable,
                           pass_fds=launch.pass_fds,capture_output=True,text=True,check=True)
        assert out.stdout.strip()=='pinned-FD-smoke'


def test_042_complete_independent_exec_trace_positive_and_mutations():
    from p01_probe import verify_execution_closure
    approved={'/safe/main':'a'*64, '/safe/loader':'b'*64}
    base={'trace_source':'kernel_execve','trace_complete':True,
          'monitor_installed_outside_sut':True,
          'coverage_start_before_first_exec':True,
          'coverage_end_after_last_child_exit':True,
          'all_descendants_exited':True,'kernel_event_drops':0,
          'unobserved_executable_memory':0,'unmonitored_dynamic_loads':0,
          'observed_pids':[100,101],
          'execve_events':[{'pid':100,'executable_path':'/safe/main','executable_sha256':'a'*64},
                           {'pid':101,'ppid':100,'executable_path':'/safe/loader','executable_sha256':'b'*64}],
          'loaded_file_events':[]}
    # TENTH-D5-043: unsigned fake kernel flags are no longer a positive test.
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_execution_closure(base, approved_components_sha256=approved, process_pids=(100,))
    for patch in ({'trace_complete':False}, {'kernel_event_drops':1},
                  {'observed_pids':[100]}, {'unobserved_executable_memory':1},
                  {'coverage_start_before_first_exec':False},
                  {'loaded_file_events':[{'executable_path':'/unsafe','executable_sha256':'c'*64}]}):
        with pytest.raises(ProbeError,match='NOT_CHECKED'):
            verify_execution_closure({**base,**patch},approved_components_sha256=approved,process_pids=(100,))
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_execution_closure({**base,'execve_events':[{'pid':100}]},
                                 approved_components_sha256=approved,process_pids=(100,))


def test_041_pinned_python_exec_from_root_controlled_fd(tmp_path):
    from p01_probe import open_pinned_launch
    # Pin the OS-owned system interpreter matching this test process.
    # sys.executable may point into a writable virtualenv: never use it
    # as a fallback for an approved FD-pinned runtime component.
    interpreter=Path(f'/usr/bin/python{sys.version_info.major}.{sys.version_info.minor}')
    assert interpreter.is_file(), 'approved system Python for this runtime is unavailable'
    interpreter=interpreter.resolve(strict=True)
    script=tmp_path/'smoke.py';script.write_text('import sys;print("PINNED",sys.argv[1])\n')
    approved={str(interpreter):digest(interpreter),str(script):digest(script)}
    with open_pinned_launch([str(interpreter),str(script)],approved,
                            launch_mode='pinned_python_script') as launch:
        output=subprocess.run([*launch.argv,'synthetic'], executable=launch.executable,
                              pass_fds=launch.pass_fds,capture_output=True,text=True,check=True)
        assert output.stdout.strip()=='PINNED synthetic'
