"""Third-review defect reproduction. These are D5 tests, not P01 acceptance PASS."""
import hashlib
import json
from pathlib import Path
import pytest
from p01_probe import ProbeError, verify_normative_expectations, verify_independent_proofs

DATA=Path(__file__).parent/'fixtures'/'p01'/'P01_ORACLES.json'

def case(ac, sid):
    items=json.loads(DATA.read_text(encoding='utf8'))['items']
    return next(s for r in items if r['ac_id']==ac for s in r['scenarios'] if s['scenario_id']==sid)

def test_third_018_no_offnode_never_deletes_protected_evidence():
    c=case('AC-N-15.2','offnode-unavailable')
    assert c['expected_observations']['protected_evidence_removed']==0
    assert c['expected_observations']['protected_evidence_sha256_before']==c['expected_observations']['protected_evidence_sha256_after']
    assert c['expected_observations']['offnode_backup_integrity_verified'] is False

def test_third_018_backup_ack_must_precede_eviction():
    c=case('AC-N-15.2','verified-offnode-and-lawful-eviction')
    assert c['expected_observations']['offnode_backup_integrity_verified'] is True
    assert c['expected_observations']['backup_verified_before_eviction'] is True
    assert c['expected_observations']['backup_digest_matches_source'] is True

def test_third_019_collector_signed_external_owner_policy_is_required():
    from p01_probe import verify_signed_collector_policy
    assert callable(verify_signed_collector_policy)

def test_third_019_untrusted_self_approved_collector_denied(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from p01_probe import verify_signed_collector_policy, _canonical
    owner=Ed25519PrivateKey.generate()
    attacker=Ed25519PrivateKey.generate()
    pub=tmp_path/'owner.pem'
    pub.write_bytes(owner.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    trusted=tmp_path/'test_collector.py';trusted.write_text('def collect(**kw): return {}\n')
    policy={'schema':'aio.p01.owner_signed_collector_policy.v1','collector_sha256':hashlib.sha256(trusted.read_bytes()).hexdigest(),'collector_path':str(trusted),
            'witness_key_path':str(tmp_path/'key'), 'git_sha':'a'*40, 'sut_uid':65534,'sut_gid':65534,'runner_uid':0,'collector_uid':65533,'collector_gid':65533,'authorized_by':'owner-independent-id', 'scope':'P01-D5','sut_command_sha256':'c'*64,'sut_repo_path':'/synthetic-test-repo','sut_executable_sha256':'d'*64, 'sut_launch_mode':'pinned_python_script', 'sut_components_sha256':{'/synthetic/python':'d'*64},'git_scan_mirror_path':'/synthetic/test-mirror','git_test_remote_url':'file:///synthetic/test-remote','synthetic_root_path':'/synthetic',
            'kernel_monitor_id':'synthetic-monitor','kernel_monitor_public_key_path':'/synthetic/monitor.pub.pem',
            'kernel_monitor_public_key_sha256':'e'*64,'kernel_monitor_socket_path':'/synthetic/monitor.sock',
            'monitor_key_isolation_probe_path':'/synthetic/monitor-isolation-guard',
            'oqa_attester_id':'synthetic-independent-attester',
            'oqa_attester_public_key_path':'/synthetic/oqa-attester.pub',
            'oqa_attester_public_key_sha256':'1'*64,
            'oqa_attester_socket_path':'/synthetic/oqa-attester.sock',
            'oqa_monitor_deployment_sha256':'2'*64,
            'oqa_observer_deployment_sha256':'3'*64,
            'readonly_observer_id':'synthetic-observer',
            'readonly_observer_public_key_path':'/synthetic/observer.pub',
            'readonly_observer_public_key_sha256':'4'*64,
            'readonly_observer_socket_path':'/synthetic/observer.sock',
            'readonly_observer_protocol':'aio.p01.readonly_snapshot.v1',
            'readonly_observer_sources':['filesystem_snapshot','sqlite_snapshot']}
    # Preserve the stricter current owner-signed OQ-09/A deployment contract.
    # This is a SYNTHETIC policy fixture, never an installed attester.
    from test_p01_twelfth_review_regressions import policy as current_oqa_policy
    policy.update({k:v for k,v in current_oqa_policy().items()
                   if k.startswith(('oqa_', 'readonly_observer_'))})
    payload=_canonical(policy)
    with pytest.raises(ProbeError,match='signature|authority'):
        verify_signed_collector_policy(payload,attacker.sign(payload),pub,collector_file=trusted,git_sha='a'*40)
    approved=verify_signed_collector_policy(payload,owner.sign(payload),pub,collector_file=trusted,git_sha='a'*40)
    assert approved['sut_uid']==65534
    # Owner signature alone must not bypass mandatory audit sensor fields.
    incomplete={k:v for k,v in policy.items() if k!='oqa_kernel_audit_public_key_sha256'}
    incomplete_bytes=_canonical(incomplete)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify_signed_collector_policy(incomplete_bytes,owner.sign(incomplete_bytes),
                                       pub,collector_file=trusted,git_sha='a'*40)

def test_third_020_same_uid_and_false_key_probe_denied(tmp_path):
    from p01_probe import require_witness_key_isolation
    key=tmp_path/'witness-key';key.write_bytes(b'x'*32);key.chmod(0o600)
    with pytest.raises(ProbeError,match='same OS identity|not isolated'):
        require_witness_key_isolation(key,sut_uid=key.stat().st_uid,sut_gid=key.stat().st_gid)

def test_third_020_actual_os_denied_for_separate_uid_when_supported(tmp_path):
    import os
    from p01_probe import require_witness_key_isolation
    if os.geteuid()!=0:
        pytest.skip('test requires isolated root test runner; no production escalation')
    # Parent directories must be searchable by unprivileged test identity;
    # otherwise ENOENT/EACCES could be caused by an inaccessible parent.
    for parent in (tmp_path.parent.parent, tmp_path.parent, tmp_path):
        parent.chmod(0o711)
    directory=tmp_path/'keyfolder';directory.mkdir(mode=0o711)
    key=directory/'witness-key';key.write_bytes(b'x'*32);key.chmod(0o600)
    assert require_witness_key_isolation(key,sut_uid=65534,sut_gid=65534)=='EACCES'

def test_third_021_reconciliation_has_independent_ordered_observations():
    o=case('AC-ERR-03.2','full-fs-result-commit-after-remote-effect')['expected_observations']
    assert o['journal_state_before_reconciliation']=='UNCERTAIN'
    assert o['journal_state_during_reconciliation']=='RECONCILING'
    assert o['remote_reconciliation_queries']==1
    assert o['remote_outcome_confirmed'] is True
    assert o['journal_state_after_reconciliation']=='CONFIRMED'
    assert o['writes_while_uncertain']==0

def test_third_022_scanner_dynamic_ref_provenance_required():
    c=case('AC-N-SEC-01.1','scan-current-tree-and-all-remote-branches')
    assert c['synthetic_input']['ref_source']=='advertised_by_test_remote'
    assert c['expected_observations']['remote_refs_discovered_independently'] is True
    assert c['expected_observations']['each_advertised_ref_sha_scanned'] is True

def test_third_022_unscanned_fourth_ref_rejected():
    from p01_probe import verify_scan_ref_coverage
    advertised={'refs/heads/main':'1'*40,'refs/heads/test-a':'2'*40,'refs/heads/test-b':'3'*40,'refs/heads/test-c':'4'*40}
    scanned={k:v for k,v in advertised.items() if k!='refs/heads/test-c'}
    with pytest.raises(ProbeError,match='unscanned|coverage|NOT_CHECKED'):
        verify_scan_ref_coverage(advertised,scanned,verified_remote=True)
    assert verify_scan_ref_coverage(advertised,advertised,verified_remote=True)

def test_third_013_os_sentinel_has_independent_existence_and_permission_proof():
    c=case('AC-N-SEC-05.4','forbidden-supervisor-path-os-denial')
    o=c['expected_observations']
    assert o['sentinel_existed_before_probe'] is True
    assert o['sentinel_digest_matches_before_after'] is True
    assert o['denial_due_to_os_permissions'] is True


def test_third_018_offnode_backup_order_not_just_boolean(tmp_path):
    """Test the actual normative gate after provenance, not a moved source line."""
    from p01_probe import TestRun, verify_normative_measurements
    c=case('AC-N-15.2','verified-offnode-and-lawful-eviction')
    assert c['synthetic_input']['require_independent_event_order'] is True
    expected_sha=c['synthetic_input']['protected_evidence_files'][0]['sha256']
    observed={**c['expected_observations'],
              'backup_verified_event_seq':12,'eviction_event_seq':13,
              'offnode_backed_up_sha256':expected_sha,
              'verified_backup_receipt_id':'synthetic-ack-001'}
    run=TestRun(pid=1818,returncode=0,command_digest='a'*64,
                fixture_digest='b'*64,workspace=tmp_path)
    assert verify_normative_measurements(c,observed,run)==observed
    wrong=(
        {'backup_verified_event_seq':14},
        {'eviction_event_seq':12},
        {'backup_verified_event_seq':True},
        {'offnode_backed_up_sha256':'0'*64},
        {'verified_backup_receipt_id':None},
    )
    for change in wrong:
        with pytest.raises(ProbeError, match='NOT_CHECKED'):
            verify_normative_measurements(c,{**observed,**change},run)


def test_third_021_trace_is_ordered():
    c=case('AC-ERR-03.2','full-fs-result-commit-after-remote-effect')
    trace=c['expected_observations']['journal_transition_trace']
    assert [(x['order'],x['journal']) for x in trace]==[(1,'UNCERTAIN'),(2,'RECONCILING'),(3,'CONFIRMED')]
    assert all(x['remote_write_count']==1 for x in trace)
