"""Test-only P01 D5 verifier and runner-side collector interface.

This code is NOT a product API and no observed AC is PASS until an approved,
separately pinned, independently reviewed collector measures a genuine SUT.
A fixture's expected observations never reach the collector.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProbeError(AssertionError):
    """NOT_CHECKED for unproven evidence, FAIL for measured AC mismatch."""


_ALLOWED_WITNESS_SOURCES = frozenset({
    'sqlite_snapshot', 'subprocess_audit', 'git_test_remote', 'filesystem_snapshot',
    'document_digest', 'http_test_server', 'offnode_stub', 'controlled_disk_fault',
    'durable_journal', 'git_history_refs', 'secret_scanner_report', 'ci_runner_exit',
    'redacted_error_log', 'os_syscall_trace', 'supervisor_inventory_metadata',
    'outbound_call_counter',
})

# Normative checks are independent of the fixture file. A snapshot digest in
# oracle_integrity adds modification detection but is NOT owner approval.
_CRITICAL_EXPECTATIONS = {
    ('AC-F-01.1', 'accepted-owner-registration', 'status'): 'PENDING_PRECHECK',
    ('AC-F-01.1', 'same-idempotency-key-again', 'registration_command_executions'): 2,
    ('AC-F-02.1', 'non-allowlisted-url', 'reason'): 'REPO_NOT_ALLOWED',
    ('AC-F-04.1', 'markdown-APPROVED-no-trust-anchor', 'worker_launches'): 0,
    ('AC-N-12.1', 'skip-mandatory-test', 'allowed'): False,
    ('AC-N-12.1', 'disable-secret-scanning', 'allowed'): False,
    ('AC-N-12.1', 'change-approved-AC-oracle', 'allowed'): False,
    ('AC-N-12.1', 'exceed-resource-cap', 'allowed'): False,
    ('AC-N-12.1', 'unauthorized-merge', 'allowed'): False,
    ('AC-N-15.1', 'log-quota-overflow', 'owned_log_bytes_after'): {'op': 'at_most', 'value': 128 * 1024 * 1024},
    ('AC-N-15.1', 'log-quota-overflow', 'log_quota_enforced'): True,
    ('AC-ERR-03.2', 'full-fs-before-durable-intent', 'remote_write_calls'): 0,
    ('AC-ERR-03.2', 'full-fs-before-durable-intent', 'system_mode'): 'FAIL_CLOSED',
    ('AC-ERR-03.2', 'full-fs-before-durable-intent', 'journal_record_created'): False,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'remote_writes_before_restart'): 1,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'remote_writes_total_after_restart'): 1,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'ack_calls'): 0,
    ('AC-N-SEC-05.5', 'exactly-next-due', 'decision'): 'DENY',
    ('AC-N-SEC-05.5', 'before-due-valid-scope', 'decision'): 'ALLOW',
    ('AC-N-SEC-05.5', 'new-ref-valid-scope', 'decision'): 'ALLOW',
    ('AC-N-SEC-05.5', 'provider-expiry-comes-first', 'decision'): 'DENY',
    ('AC-N-15.2', 'evidence-512MiB-without-offnode', 'reason'): 'ARTIFACT_QUOTA_BLOCKED',
    ('AC-N-15.2', 'offnode-unavailable', 'protected_evidence_removed'): 0,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'journal_state_before_reconciliation'): 'UNCERTAIN',
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'journal_state_after_reconciliation'): 'CONFIRMED',
    ('AC-N-SEC-01.1', 'scan-current-tree-and-all-remote-branches', 'each_advertised_ref_sha_scanned'): True,
}


# Only an out-of-band, OWNER-AUTHENTICATED trust root is allowed to authorize
# the collector in real acceptance.  These are fixed runner-side locations;
# untrusted SUT/runtime environment variables cannot select an alternative key.
OWNER_PUBLIC_KEY_PATH = Path('/etc/aio-orchestrator/trust/owner-ed25519.pub.pem')
OWNER_SIGNED_POLICY_PATH = Path('/etc/aio-orchestrator/trust/p01-collector-policy.json')
OWNER_POLICY_SIGNATURE_PATH = Path('/etc/aio-orchestrator/trust/p01-collector-policy.sig')


def verify_signed_collector_policy(payload: bytes, signature: bytes, pinned_owner_public_key: Path,
                                   *, collector_file: Path, git_sha: str) -> dict[str, Any]:
    """Authenticate approval with a separately provisioned owner public key.

    Ownership/provisioning of the key is a separate owner-inspection requirement;
    a caller-provided public key alone is NOT an authorization proof.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise ProbeError('NOT_CHECKED: required signature verifier unavailable') from exc
    try:
        key=load_pem_public_key(pinned_owner_public_key.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError('not Ed25519')
        key.verify(signature, payload)
    except (OSError, ValueError, InvalidSignature) as exc:
        raise ProbeError('NOT_CHECKED: owner authority signature invalid') from exc
    try:
        data=json.loads(payload)
    except ValueError as exc:
        raise ProbeError('NOT_CHECKED: malformed signed policy') from exc
    required={'schema','collector_sha256','collector_path','witness_key_path','git_sha',
              'sut_uid','sut_gid','runner_uid','authorized_by','scope',
              'sut_command_sha256','sut_repo_path'}
    if not isinstance(data,dict) or not required <= set(data) or data['schema']!='aio.p01.owner_signed_collector_policy.v1':
        raise ProbeError('NOT_CHECKED: incomplete signed collector policy')
    if data['scope']!='P01-D5' or not data['authorized_by'] or data['git_sha']!=git_sha:
        raise ProbeError('NOT_CHECKED: signed policy wrong scope, SHA or actor')
    if data['collector_path']!=str(collector_file.resolve(strict=True)):
        raise ProbeError('NOT_CHECKED: signed policy collector path mismatch')
    if data['collector_sha256']!=_sha256(collector_file.read_bytes()):
        raise ProbeError('NOT_CHECKED: signed policy collector digest mismatch')
    for field in ('sut_uid','sut_gid','runner_uid'):
        if type(data[field]) is not int or data[field]<0:
            raise ProbeError('NOT_CHECKED: signed policy OS identity invalid')
    if not isinstance(data['sut_command_sha256'],str) or len(data['sut_command_sha256'])!=64:
        raise ProbeError('NOT_CHECKED: SUT command not pinned in signed policy')
    if not Path(data['sut_repo_path']).is_absolute():
        raise ProbeError('NOT_CHECKED: SUT checkout not pinned by signed policy')
    if data['sut_uid']==data['runner_uid']:
        raise ProbeError('NOT_CHECKED: signed policy selects same OS identity')
    if not Path(data['witness_key_path']).is_absolute():
        raise ProbeError('NOT_CHECKED: untrusted relative witness key path')
    return data


def load_externally_approved_runner_policy(*, git_sha: str) -> dict[str, Any]:
    """Out-of-band root must be installed by OWNER; never choose it via env."""
    trust_directory=OWNER_PUBLIC_KEY_PATH.parent
    if (trust_directory!=OWNER_SIGNED_POLICY_PATH.parent or
            trust_directory!=OWNER_POLICY_SIGNATURE_PATH.parent):
        raise ProbeError('NOT_CHECKED: inconsistent approved trust directory')
    for ancestor in (trust_directory, *list(trust_directory.parents)):
        if ancestor.is_symlink() or ancestor.stat().st_uid!=0 or ancestor.stat().st_mode & 0o022:
            raise ProbeError('NOT_CHECKED: trust root directory is not root-controlled')
    for path in (OWNER_PUBLIC_KEY_PATH, OWNER_SIGNED_POLICY_PATH, OWNER_POLICY_SIGNATURE_PATH):
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_mode & 0o022:
                raise ProbeError('NOT_CHECKED: untrusted owner policy filesystem permissions')
        except OSError as exc:
            raise ProbeError('NOT_CHECKED: owner policy trust root not provisioned') from exc
    try:
        payload=OWNER_SIGNED_POLICY_PATH.read_bytes()
        signed=json.loads(payload)
        collector_file=Path(signed['collector_path'])
        signature=OWNER_POLICY_SIGNATURE_PATH.read_bytes()
        return verify_signed_collector_policy(payload, signature, OWNER_PUBLIC_KEY_PATH,
                                               collector_file=collector_file, git_sha=git_sha)
    except (OSError, ValueError, KeyError) as exc:
        raise ProbeError('NOT_CHECKED: authenticated owner collector approval missing') from exc


def require_witness_key_isolation(key_path: Path, *, sut_uid: int, sut_gid: int) -> str:
    """Real negative syscall executed as the SUT OS identity, with NO key value output.

    Required before *every* acceptance run. Test-only uses a synthetic key.
    If the runner cannot setuid to SUT, fail closed (never claim OS PASS).
    """
    import os
    import subprocess
    import sys
    if sut_uid==os.geteuid() or sut_uid==key_path.stat().st_uid:
        raise ProbeError('NOT_CHECKED: same OS identity, witness key not isolated')
    if key_path.stat().st_mode & 0o077:
        raise ProbeError('NOT_CHECKED: witness key permissions expose runner authority')
    snippet=(
        'import os,sys,errno; p=sys.argv[1]; '
        'os.stat(p); '
        '\ntry: fd=os.open(p,os.O_RDONLY)\n'
        'except OSError as e: sys.exit(0 if e.errno in (errno.EACCES,errno.EPERM) else 42)\n'
        'else: os.close(fd);sys.exit(43)'
    )
    try:
        child=subprocess.run([sys.executable,'-c',snippet,str(key_path)],
                             env={'PATH':'/usr/bin:/bin'},user=sut_uid,group=sut_gid,
                             capture_output=True,timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProbeError('NOT_CHECKED: cannot run isolation probe as SUT identity') from exc
    if child.returncode!=0:
        raise ProbeError('NOT_CHECKED: synthetic witness key OS denial not proven')
    return 'EACCES'


def verify_scan_ref_coverage(advertised: dict[str,str], scanned: dict[str,str],
                             *, verified_remote: bool) -> bool:
    """Cross-check complete independently advertised remote branches against scans."""
    if not verified_remote or not isinstance(advertised,dict) or not advertised:
        raise ProbeError('NOT_CHECKED: remote refs were not independently enumerated')
    if not isinstance(scanned,dict) or advertised!=scanned or any(
        not isinstance(k,str) or not k.startswith('refs/heads/') or
        not isinstance(v,str) or len(v)!=40 or any(c not in '0123456789abcdef' for c in v)
        for k,v in advertised.items()
    ):
        raise ProbeError('NOT_CHECKED: unscanned or mismatched remote ref SHA coverage')
    return True


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_normative_expectations(items: list[dict[str, Any]]) -> None:
    for (ac, sid, field), required in _CRITICAL_EXPECTATIONS.items():
        rows = [r for r in items if r['ac_id'] == ac]
        if len(rows) != 1:
            raise ProbeError(f'NOT_CHECKED: missing/duplicated AC {ac}')
        cases = [s for s in rows[0]['scenarios'] if s['scenario_id'] == sid]
        if len(cases) != 1 or cases[0]['expected_observations'].get(field) != required:
            raise ProbeError(f'NOT_CHECKED: changed normative expectation {ac}/{sid}/{field}')
    for row in items:
        for case in row['scenarios']:
            if not case.get('synthetic_input', {}).get('operation'):
                raise ProbeError(f'NOT_CHECKED: missing operation {row["ac_id"]}/{case["scenario_id"]}')
            if not isinstance(case.get('expected_observations'), dict) or not case['expected_observations']:
                raise ProbeError('NOT_CHECKED: missing expectations')
            if row['ac_id'] == 'AC-N-SEC-05.5' and case['expected_observations']['decision'] == 'DENY':
                if case['expected_observations'].get('outbound_calls') != 0:
                    raise ProbeError('NOT_CHECKED: DENY cannot permit outbound')
            if row['ac_id'] == 'AC-N-SEC-05.4' and 'expect_errno' in case['synthetic_input']:
                if case['expected_observations'].get('actual_errno') != case['synthetic_input']['expect_errno']:
                    raise ProbeError('NOT_CHECKED: OS errno expectation missing')


@dataclass(frozen=True)
class TestRun:
    __test__ = False
    pid: int
    returncode: int
    command_digest: str
    fixture_digest: str
    workspace: Path
    git_sha: str = ''
    run_id: str = ''
    process_start_ticks: int = 0
    process_pids: tuple[int, ...] = ()
    returncodes: tuple[int, ...] = ()
    collector_sha256: str = ''


@dataclass(frozen=True)
class IndependentProof:
    source: str
    path: Path
    sha256: str
    captures: dict[str, Any]
    run_pid: int
    fixture_digest: str
    witness_mac: str
    run_id: str = ''
    git_sha: str = ''
    run_command_digest: str = ''
    run_returncode: int | None = None
    process_start_ticks: int = 0


def _run_identity(run: TestRun) -> dict[str, Any]:
    return {'git_sha': run.git_sha, 'run_id': run.run_id, 'pid': run.pid,
            'returncode': run.returncode, 'command_digest': run.command_digest,
            'fixture_digest': run.fixture_digest,
            'process_start_ticks': run.process_start_ticks,
            'process_pids': list(run.process_pids), 'returncodes': list(run.returncodes),
            'collector_sha256': run.collector_sha256}


def _evidence_mac(key: bytes, proof: IndependentProof) -> str:
    signed = [proof.source, str(proof.path.resolve()), proof.sha256, proof.run_pid,
              proof.fixture_digest, proof.captures, proof.run_id, proof.git_sha,
              proof.run_command_digest, proof.run_returncode, proof.process_start_ticks]
    return hmac.new(key, _canonical(signed), hashlib.sha256).hexdigest()


def _parse_witness(proof: IndependentProof, run: TestRun) -> dict[str, Any]:
    try:
        observations = json.loads(proof.path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ProbeError('NOT_CHECKED: witness JSON invalid') from exc
    if observations.get('schema') != 'aio.p01.independent_witness.v1':
        raise ProbeError('NOT_CHECKED: missing witness schema')
    if observations.get('source') != proof.source or observations.get('run') != _run_identity(run):
        raise ProbeError('NOT_CHECKED: witness run metadata mismatch')
    capture = observations.get('measurement')
    if not isinstance(capture, dict) or not capture:
        raise ProbeError('NOT_CHECKED: witness measurements absent')
    if capture != proof.captures:
        raise ProbeError('NOT_CHECKED: captures not extracted from authenticated witness bytes')
    return capture


def verify_independent_proofs(
    case: dict[str, Any], reported_by_sut: dict[str, Any],
    evidence: dict[str, IndependentProof], run: TestRun | None, *,
    trusted_witness_key: bytes | None = None,
    expected_git_sha: str | None = None,
    expected_command_digest: str | None = None,
    expected_collector_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify *external* measurements, ignoring all SUT-reported values.

    This verifier cannot authenticate a collector itself: the authorized runner
    must pin its bytes and not expose key/collector/evidence to the SUT. Its
    unit-test MAC fixtures are not proof of a real execution.
    """
    if run is None or not isinstance(run, TestRun) or run.pid <= 0:
        raise ProbeError('NOT_CHECKED: actual subprocess PID missing')
    if not trusted_witness_key or len(trusted_witness_key) < 32:
        raise ProbeError('NOT_CHECKED: independent runner witness authority absent')
    if not expected_git_sha or run.git_sha != expected_git_sha or len(run.git_sha) != 40:
        raise ProbeError('NOT_CHECKED: unpinned or mismatched Git HEAD SHA')
    if not expected_command_digest or run.command_digest != expected_command_digest:
        raise ProbeError('NOT_CHECKED: unpinned or mismatched command')
    if not expected_collector_sha256 or run.collector_sha256 != expected_collector_sha256 or len(run.collector_sha256) != 64:
        raise ProbeError('NOT_CHECKED: unpinned or mismatched trusted collector digest')
    if not run.run_id or run.process_start_ticks <= 0:
        raise ProbeError('NOT_CHECKED: missing runner issued execution identity')
    if not run.process_pids or run.pid != run.process_pids[-1] or not run.returncodes:
        raise ProbeError('NOT_CHECKED: missing recorded subprocess sequence')
    if len(run.process_pids) != len(run.returncodes):
        raise ProbeError('NOT_CHECKED: subprocess audit length mismatch')
    if run.returncode != run.returncodes[-1]:
        raise ProbeError('NOT_CHECKED: subprocess returncode mismatch')
    digest = _sha256(_canonical(case['synthetic_input']))
    if run.fixture_digest != digest:
        raise ProbeError('NOT_CHECKED: fixture digest mismatch')
    if not run.workspace.is_dir():
        raise ProbeError('NOT_CHECKED: test workspace absent')
    trusted_dir = (run.workspace.parent / 'trusted_evidence').resolve()
    observed = {}
    for item in case['independent_proofs']:
        source = item['source']
        if source not in _ALLOWED_WITNESS_SOURCES:
            raise ProbeError(f'NOT_CHECKED: unsupported witness {source}')
        proof = evidence.get(source)
        if not isinstance(proof, IndependentProof) or proof.source != source:
            raise ProbeError(f'NOT_CHECKED: independent {source} witness missing')
        if proof.run_pid != run.pid or proof.fixture_digest != digest or proof.run_id != run.run_id:
            raise ProbeError(f'NOT_CHECKED: witness for wrong execution: {source}')
        if (proof.git_sha != run.git_sha or proof.run_command_digest != run.command_digest
                or proof.run_returncode != run.returncode or proof.process_start_ticks != run.process_start_ticks):
            raise ProbeError(f'NOT_CHECKED: {source} witness execution provenance mismatch')
        if not proof.path.is_file() or not proof.path.resolve().is_relative_to(trusted_dir):
            raise ProbeError(f'NOT_CHECKED: {source} witness outside trusted evidence directory')
        if not hmac.compare_digest(_sha256(proof.path.read_bytes()), proof.sha256):
            raise ProbeError(f'NOT_CHECKED: {source} witness contents mutated')
        if not hmac.compare_digest(_evidence_mac(trusted_witness_key, proof), proof.witness_mac):
            raise ProbeError(f'NOT_CHECKED: {source} witness was not captured by trusted runner')
        for key, value in _parse_witness(proof, run).items():
            if key in observed and observed[key] != value:
                raise ProbeError(f'NOT_CHECKED: inconsistent witness measurement {key}')
            observed[key] = value
    if (case['synthetic_input'].get('operation')=='run_evidence_quota_gate' and
            case['synthetic_input'].get('eviction_allowed')):
        expected_sha=case['synthetic_input']['protected_evidence_files'][0]['sha256']
        backup_seq, eviction_seq=observed.get('backup_verified_event_seq'),observed.get('eviction_event_seq')
        if (type(backup_seq) is not int or type(eviction_seq) is not int or
                backup_seq < 0 or eviction_seq <= backup_seq or
                observed.get('offnode_backed_up_sha256') != expected_sha or
                not observed.get('verified_backup_receipt_id')):
            raise ProbeError('NOT_CHECKED: no independently confirmed intact offnode backup before eviction')
    if case['synthetic_input'].get('required_independent_reconciliation_trace'):
        trace=observed.get('journal_transition_trace')
        if (not isinstance(trace,list) or len(trace)!=3 or
                [e.get('order') for e in trace if isinstance(e,dict)] != [1,2,3] or
                [e.get('journal') for e in trace if isinstance(e,dict)] !=
                  ['UNCERTAIN','RECONCILING','CONFIRMED']):
            raise ProbeError('NOT_CHECKED: missing independent ordered reconciliation evidence')
    if case['synthetic_input'].get('require_preexisting_test_sentinel'):
        before=observed.get('sentinel_sha256_before')
        after=observed.get('sentinel_sha256_after')
        if (observed.get('sentinel_existed_before_probe') is not True or
                before!=case['synthetic_input']['sentinel_sha256'] or after!=before):
            raise ProbeError('NOT_CHECKED: pre-existing synthetic sentinel integrity not established')
    if case['synthetic_input'].get('require_preexisting_listening_test_server'):
        if observed.get('endpoint_listening_before_probe') is not True or observed.get('denial_due_to_network_os_policy') is not True:
            raise ProbeError('NOT_CHECKED: network OS policy denial on listening endpoint not proven')
    if case['synthetic_input'].get('operation')=='scan_git_tree_and_history':
        verify_scan_ref_coverage(observed.get('remote_advertised_ref_sha'),
                                 observed.get('scanned_ref_sha'),
                                 verified_remote=observed.get('remote_refs_verified_by_collector') is True)
    for key, expected in case['expected_observations'].items():
        if key not in observed:
            raise ProbeError(f'NOT_CHECKED: no independent observation for {key}')
        if isinstance(expected, dict) and expected.get('op') == 'at_most' and set(expected) == {'op', 'value'}:
            if type(observed[key]) not in (int, float) or type(expected['value']) not in (int, float) or observed[key] > expected['value'] or observed[key] < 0:
                raise ProbeError(f'FAIL: measured quota exceeds limit for {key}')
        elif observed[key] != expected:
            raise ProbeError(f'FAIL: independent measurement differs for {key}')
    return observed


def _load_pinned_collector(collector_file: Path, approved_sha256: str, workspace: Path):
    """Only runner-configured, hash-pinned collectors outside SUT workspace."""
    path = collector_file.resolve(strict=True)
    if path.is_relative_to(workspace.resolve()):
        raise ProbeError('NOT_CHECKED: collector in SUT-writable workspace')
    if _sha256(path.read_bytes()) != approved_sha256:
        raise ProbeError('NOT_CHECKED: external collector digest mismatch')
    if path.stat().st_mode & 0o022:
        raise ProbeError('NOT_CHECKED: collector file writable by group/others')
    spec = importlib.util.spec_from_file_location('aio_external_approved_test_collector', path)
    if spec is None or spec.loader is None:
        raise ProbeError('NOT_CHECKED: approved collector could not be imported')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    callback = getattr(module, 'collect', None)
    if not callable(callback):
        raise ProbeError('NOT_CHECKED: trusted collector lacks collect()')
    return callback


def collect_trusted_evidence(*, synthetic_input: dict[str, Any], required_sources: list[str],
                             run: TestRun, collector_file: Path, collector_sha256: str,
                             witness_key: bytes) -> dict[str, IndependentProof]:
    """Trusted runner calls independently pinned collector; never sends EXPECTED values.

    The plugin is a test-only integration seam. Real OS/CI/Git collectors must
    be independently reviewed, deployed outside SUT, and run only in sandbox.
    A mock callback that copies expectations is forbidden as acceptance evidence.
    """
    if len(witness_key) < 32:
        raise ProbeError('NOT_CHECKED: witness authority absent')
    if run.collector_sha256 != collector_sha256:
        raise ProbeError('NOT_CHECKED: collector pin not bound to run')
    collect = _load_pinned_collector(collector_file, collector_sha256, run.workspace)
    trusted_dir = run.workspace.parent / 'trusted_evidence'
    trusted_dir.mkdir(mode=0o700, exist_ok=False)
    if any(source not in _ALLOWED_WITNESS_SOURCES for source in required_sources):
        raise ProbeError('NOT_CHECKED: unknown collector source')
    # Plugin must READ independent OS/FS/CI/Git artefacts; it cannot see the
    # expected observations, can only receive immutable inputs and run identity.
    measurements = collect(synthetic_input=synthetic_input, run=run,
                           required_sources=frozenset(required_sources))
    if not isinstance(measurements, dict):
        raise ProbeError('NOT_CHECKED: collector returned invalid measurements')
    output = {}
    for source in required_sources:
        capture = measurements.get(source)
        if not isinstance(capture, dict) or not capture:
            raise ProbeError(f'NOT_CHECKED: collector has no measured {source}')
        payload = {'schema': 'aio.p01.independent_witness.v1', 'source': source,
                   'run': _run_identity(run), 'measurement': capture}
        path = trusted_dir / f'{source}.json'
        with path.open('xb') as handle:
            handle.write(_canonical(payload))
        unsigned = IndependentProof(source=source, path=path, sha256=_sha256(path.read_bytes()),
                                    captures=capture, run_pid=run.pid, fixture_digest=run.fixture_digest,
                                    witness_mac='', run_id=run.run_id, git_sha=run.git_sha,
                                    run_command_digest=run.command_digest,
                                    run_returncode=run.returncode, process_start_ticks=run.process_start_ticks)
        output[source] = IndependentProof(**{**vars(unsigned), 'witness_mac': _evidence_mac(witness_key, unsigned)})
    return output
