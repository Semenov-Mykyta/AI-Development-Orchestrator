"""Tenth D5 red-first tests. Test keys and monitor stubs are synthetic only.

These validate the future runner/monitor contract, NOT a kernel audit deployment.
"""
import hashlib
import os
from pathlib import Path
import pytest

from p01_probe import ProbeError, verify_execution_closure, open_pinned_launch


def _old_accepted_claim():
    return {'trace_source':'kernel_execve','trace_complete':True,
            'monitor_installed_outside_sut':True,
            'coverage_start_before_first_exec':True,
            'coverage_end_after_last_child_exit':True,
            'all_descendants_exited':True,'kernel_event_drops':0,
            'unobserved_executable_memory':0,'unmonitored_dynamic_loads':0,
            'observed_pids':[301],
            'execve_events':[{'pid':301,'executable_path':'/signed/main','executable_sha256':'a'*64}],
            'loaded_file_events':[]}


def test_043_bare_monitor_claim_without_attested_session_is_denied():
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_execution_closure(_old_accepted_claim(),approved_components_sha256={'/signed/main':'a'*64},process_pids=(301,))


def test_043_monitor_identity_requires_separate_trust_key():
    from p01_probe import verify_monitor_receipt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key=Ed25519PrivateKey.generate()
    receipt={'schema':'aio.p01.kernel_monitor_armed.v1','monitor_id':'approved-monitor',
             'run_id':'synthetic-run','git_sha':'a'*40,'command_digest':'b'*64,
             'monitor_session_id':'synthetic-session','armed_monotonic_ns':100,'coverage_scope':'all_sut_descendants'}
    import p01_probe
    signature=key.sign(p01_probe._canonical(receipt)).hex()
    stranger=Ed25519PrivateKey.generate().public_key()
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_monitor_receipt(receipt,signature,stranger,expected_schema='aio.p01.kernel_monitor_armed.v1',
                               expected_monitor_id='approved-monitor',expected_run_id='synthetic-run',
                               expected_git_sha='a'*40,expected_command_digest='b'*64)


def test_043_monitor_ready_receipt_must_precede_execution():
    from p01_probe import verify_monitor_session
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_monitor_session(None,None,launch_monotonic_ns=1000,expected_run_id='synthetic-run',
                               expected_monitor_id='test-monitor',expected_git_sha='a'*40,expected_command_digest='b'*64)


def test_043_parent_child_ancestry_requires_real_edges():
    from p01_probe import verify_execution_ancestry
    events=[{'pid':301,'ppid':1,'start_monotonic_ns':101},
            {'pid':302,'ppid':9999,'start_monotonic_ns':102}]
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_execution_ancestry(events,roots=(301,),observed_pids=(301,302))


def test_044_unreadable_pinned_script_rejected_as_not_checked(tmp_path):
    if os.geteuid()!=0: pytest.skip('OS uid isolation requires test-only root container')
    from p01_probe import require_pinned_script_access
    import sys
    script=tmp_path/'script.py'
    script.write_text('pass\n'); script.chmod(0o600)
    with open_pinned_launch([str(Path('/usr/bin/python3.13').resolve()),str(script)],
                            {str(Path('/usr/bin/python3.13').resolve()):hashlib.sha256(Path('/usr/bin/python3.13').resolve().read_bytes()).hexdigest(),
                             str(script):hashlib.sha256(script.read_bytes()).hexdigest()},
                            launch_mode='pinned_python_script') as launch:
        with pytest.raises(ProbeError,match='NOT_CHECKED'):
            require_pinned_script_access(launch, sut_uid=65534,sut_gid=65534)


def test_044_readable_script_passes_access_preflight(tmp_path):
    if os.geteuid()!=0: pytest.skip('OS uid isolation requires test-only root container')
    from p01_probe import require_pinned_script_access
    script=tmp_path/'script.py';script.write_text('pass\n'); script.chmod(0o644)
    exe=Path('/usr/bin/python3.13').resolve()
    with open_pinned_launch([str(exe),str(script)],
                            {str(exe):hashlib.sha256(exe.read_bytes()).hexdigest(),
                             str(script):hashlib.sha256(script.read_bytes()).hexdigest()},
                            launch_mode='pinned_python_script') as launch:
        assert require_pinned_script_access(launch,sut_uid=65534,sut_gid=65534)


def signed_monitor_case():
    """Pure unit fixture: ephemeral fake sidecar signer; NOT independent OS evidence."""
    from p01_probe import _sha256,_canonical
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key=Ed25519PrivateKey.generate()
    session='signed-test-session'
    run='signed-test-run'
    sha='a'*40
    cmd='b'*64
    monitor='approved-test-monitor'
    ready={'schema':'aio.p01.kernel_monitor_armed.v1','monitor_id':monitor,
           'monitor_session_id':session,'run_id':run,'git_sha':sha,
           'command_digest':cmd,'coverage_scope':'all_sut_descendants',
           'armed_monotonic_ns':100,'monitor_boot_id':'synthetic-boot-uuid'}
    events=[{'pid':301,'ppid':1,'start_monotonic_ns':120,'executable_path':'/signed/main','executable_sha256':'a'*64},
            {'pid':302,'ppid':301,'start_monotonic_ns':130,'executable_path':'/signed/child','executable_sha256':'b'*64}]
    loads=[{'pid':301,'executable_path':'/signed/lib','executable_sha256':'c'*64}]
    observed=[301,302]
    capture={'trace_source':'kernel_execve','trace_complete':True,'monitor_installed_outside_sut':True,
             'coverage_start_before_first_exec':True,'coverage_end_after_last_child_exit':True,
             'all_descendants_exited':True,'kernel_event_drops':0,'unobserved_executable_memory':0,
             'unmonitored_dynamic_loads':0,'observed_pids':observed,'execve_events':events,
             'loaded_file_events':loads}
    stop={'schema':'aio.p01.kernel_monitor_stopped.v1','monitor_id':monitor,
          'monitor_session_id':session,'run_id':run,'git_sha':sha,'command_digest':cmd,
          'monitor_boot_id':'synthetic-boot-uuid','coverage_scope':'all_sut_descendants',
          'monitor_isolated_from_sut':True,'monitor_loss_counter_from_kernel':True,
          'kernel_event_drops':0,'uninterrupted_coverage':True,'all_descendants_exited':True,
          'file_load_coverage_complete':True,'unmonitored_dynamic_loads':0,
          'unobserved_executable_memory':0,
          'first_exec_monotonic_ns':120,'last_exit_monotonic_ns':200,
          'stopped_monotonic_ns':210,
          'event_sha256':_sha256(_canonical({'execve_events':events,'loaded_file_events':loads,
                                           'observed_pids':observed,'kernel_event_drops':0}))}
    capture['monitor_stopped_receipt']=stop
    capture['monitor_stopped_signature']=key.sign(_canonical(stop)).hex()
    from p01_probe import _canonical
    ready_envelope={'receipt':ready,'signature':key.sign(_canonical(ready)).hex()}
    params={'approved_components_sha256':{'/signed/main':'a'*64,'/signed/child':'b'*64,'/signed/lib':'c'*64},
            'process_pids':(301,),'monitor_public_key':key.public_key(),
            'monitor_ready_receipt':ready_envelope,'monitor_id':monitor,'run_id':run,'git_sha':sha,
            'command_digest':cmd,'launch_monotonic_ns':110}
    return key, capture, params


def test_043_external_monitor_attested_full_graph_unit_positive():
    from p01_probe import verify_execution_closure
    _,capture,params=signed_monitor_case()
    assert verify_execution_closure(capture,**params)


@pytest.mark.parametrize('mutation', ['wrong_signature','wrong_events','wrong_monitor_key',
                                      'wrong_run','late_arm','missing_parent','lost_counter',
                                      'unchecked_load','disconnected_child','fake_arm_signature'])
def test_043_attested_trace_mutations_fail_closed(mutation):
    from p01_probe import verify_execution_closure
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _,capture,params=signed_monitor_case()
    if mutation=='wrong_signature': capture['monitor_stopped_signature']='00'*64
    elif mutation=='wrong_events': capture['execve_events'][1]['executable_sha256']='c'*64
    elif mutation=='wrong_monitor_key': params['monitor_public_key']=Ed25519PrivateKey.generate().public_key()
    elif mutation=='wrong_run': params['run_id']='other-run'
    elif mutation=='late_arm': params['launch_monotonic_ns']=99
    elif mutation=='missing_parent': capture['execve_events'][1]['ppid']=9999
    elif mutation=='lost_counter': capture['kernel_event_drops']=1
    elif mutation=='unchecked_load': capture['loaded_file_events'][0]['pid']=9999
    elif mutation=='disconnected_child': capture['observed_pids'].append(777)
    elif mutation=='fake_arm_signature': params['monitor_ready_receipt']['signature']='00'*64
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_execution_closure(capture,**params)


def test_043_unattributed_self_report_cannot_create_signed_trace():
    from p01_probe import verify_execution_closure
    _,capture,params=signed_monitor_case()
    # Correct-looking flags and a valid HMAC from the collector cannot sign
    # a new monitor-specific run; the authority is independent.
    capture['monitor_stopped_receipt']['monitor_boot_id']='forged-boot'
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_execution_closure(capture,**params)


def test_043_monitor_arm_socket_requires_real_independently_signed_ack(tmp_path):
    """Synthetic socket stub only; owner-authorized monitor deployment NOT tested."""
    import socket,threading,time,json
    from p01_probe import arm_monitor_session,verify_monitor_session,_canonical
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if os.geteuid()!=0: pytest.skip('socket ownership guard requires test root')
    signer=Ed25519PrivateKey.generate()
    path=tmp_path/'synthetic-monitor.sock'
    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    server.bind(str(path)); path.chmod(0o600);server.listen(1)
    def server_one():
        with server.accept()[0] as peer:
            payload=b''
            while not payload.endswith(b'\n'):
                payload+=peer.recv(4096)
            request=json.loads(payload)
            receipt={'schema':'aio.p01.kernel_monitor_armed.v1',
                     'monitor_id':request['monitor_id'],'run_id':request['run_id'],
                     'git_sha':request['git_sha'],'command_digest':request['command_digest'],
                     'monitor_session_id':'synthetic-sidecar-session',
                     'armed_monotonic_ns':time.monotonic_ns(),
                     'monitor_boot_id':'synthetic-boot',
                     'coverage_scope':'all_sut_descendants'}
            response={'receipt':receipt,'signature':signer.sign(_canonical(receipt)).hex()}
            peer.sendall(_canonical(response)+b'\n')
    thread=threading.Thread(target=server_one,daemon=True);thread.start()
    try:
        receipt=arm_monitor_session(socket_path=path,
            monitor_public_key=signer.public_key(),monitor_id='test-monitor',
            run_id='test-arm-run',git_sha='a'*40,command_digest='b'*64,sut_uid=65534)
        assert receipt['receipt']['monitor_session_id']=='synthetic-sidecar-session'
        assert verify_monitor_session(receipt,signer.public_key(),
                                      expected_run_id='test-arm-run',expected_monitor_id='test-monitor',
                                      expected_git_sha='a'*40,expected_command_digest='b'*64,
                                      launch_monotonic_ns=time.monotonic_ns())
    finally:
        thread.join(timeout=5);server.close();path.unlink(missing_ok=True)


def test_043_monitor_missing_before_popen_is_not_checked(tmp_path):
    from p01_probe import arm_monitor_session
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        arm_monitor_session(socket_path=tmp_path/'no-monitor.sock',
            monitor_public_key=Ed25519PrivateKey.generate().public_key(),
            monitor_id='test-monitor',run_id='run',git_sha='a'*40,
            command_digest='b'*64,sut_uid=65534)
