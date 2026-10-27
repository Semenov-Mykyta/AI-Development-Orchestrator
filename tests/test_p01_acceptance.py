"""P01 D5 synthetic acceptance driver: does not implement P01 or generate fake PASS.

Launch SUT only in separately approved OQ-09/A sandbox with an independently
hash-pinned trusted collector. Unit-verifier fixtures never imply SUT evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import uuid

import pytest
from p01_probe import (ProbeError, TestRun, collect_trusted_evidence,
                       verify_independent_proofs, verify_normative_expectations, _canonical,
                       load_externally_approved_runner_policy, require_witness_key_isolation,
                       verify_sut_proc_identity, verify_immutable_sut_checkout,
                       materialize_synthetic_objects, require_preexisting_synthetic_sentinel,
                       require_sut_synthetic_evidence_access, open_pinned_launch,
                       verify_execution_closure)

ORACLE = Path(__file__).resolve().parent / 'fixtures' / 'p01' / 'P01_ORACLES.json'
ITEMS = json.loads(ORACLE.read_text('utf8'))['items']
verify_normative_expectations(ITEMS)
TEST_CASES = [(r['ac_id'], s) for r in ITEMS if r['auto_test_required'] for s in r['scenarios']]


def _start_ticks(pid: int) -> int:
    """Linux /proc starttime read while child is alive to prevent PID-only binding."""
    try:
        return int(Path(f'/proc/{pid}/stat').read_text('utf8').rsplit(')', 1)[1].split()[19])
    except (OSError, IndexError, ValueError) as exc:
        raise ProbeError('NOT_CHECKED: no OS process starttime') from exc


@pytest.fixture(scope='session')
def approved_test_subprocess():
    command = os.environ.get('AIO_P01_SUT_COMMAND')
    repo = os.environ.get('AIO_P01_SUT_REPO')
    git_sha = os.environ.get('AIO_P01_APPROVED_SUT_SHA')
    if not all((command, repo, git_sha)):
        pytest.fail('NOT_CHECKED: SUT SHA and runner not approved', pytrace=False)
    try:
        policy = load_externally_approved_runner_policy(git_sha=git_sha)
        collector=policy['collector_path']
        digest=policy['collector_sha256']
        keypath=policy['witness_key_path']
        sut_uid,sut_gid=policy['sut_uid'],policy['sut_gid']
        if policy['runner_uid']!=os.geteuid():
            raise ProbeError('NOT_CHECKED: runner OS identity not approved')
        # Only a successful REAL denied syscall qualifies as a key isolation proof.
        require_witness_key_isolation(Path(keypath),sut_uid=sut_uid,sut_gid=sut_gid)
    except (ProbeError, OSError) as exc:
        pytest.fail(str(exc),pytrace=False)
    argv = shlex.split(command)
    if (hashlib.sha256(_canonical(argv)).hexdigest()!=policy['sut_command_sha256'] or
            str(Path(repo).resolve())!=policy['sut_repo_path']):
        pytest.fail('NOT_CHECKED: SUT command/repo not approved in signed policy',pytrace=False)
    if not argv or not Path(argv[0]).is_absolute() or not Path(argv[0]).is_file():
        pytest.fail('NOT_CHECKED: invalid approved absolute SUT binary', pytrace=False)
    if len(git_sha) != 40:
        pytest.fail('NOT_CHECKED: exact approved Git HEAD SHA required', pytrace=False)
    try:
        actual_git = subprocess.run(['git', '-C', repo, 'rev-parse', 'HEAD'],
                                    capture_output=True, check=True, timeout=5, text=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pytest.fail('NOT_CHECKED: cannot independently inspect checked out SUT HEAD', pytrace=False)
    if actual_git != git_sha:
        pytest.fail('NOT_CHECKED: Git HEAD does not match approved SUT SHA', pytrace=False)
    try:
        verify_immutable_sut_checkout(Path(repo), git_sha, argv, policy['sut_executable_sha256'],
                                      approved_components_sha256=policy['sut_components_sha256'],
                                      approved_launch_mode=policy['sut_launch_mode'])
    except ProbeError as exc:
        pytest.fail(str(exc), pytrace=False)
    # Collector and witness key belong to a different trust domain from SUT.
    for secure_path in (collector, keypath):
        if Path(secure_path).resolve().is_relative_to(Path(repo).resolve()):
            pytest.fail('NOT_CHECKED: trust material inside SUT checkout', pytrace=False)
    try:
        key = Path(keypath).read_bytes()
    except OSError:
        pytest.fail('NOT_CHECKED: runner-only witness key unavailable', pytrace=False)
    if len(key) < 32:
        pytest.fail('NOT_CHECKED: weak/absent witness key', pytrace=False)
    if Path(keypath).stat().st_mode & 0o077:
        pytest.fail('NOT_CHECKED: witness key accessible outside owner', pytrace=False)
    trusted_git_mirror=Path(policy['git_scan_mirror_path'])
    if trusted_git_mirror.resolve().is_relative_to(Path(repo).resolve()):
        pytest.fail('NOT_CHECKED: test Git remote inside SUT checkout',pytrace=False)
    return argv, git_sha, Path(collector), digest, key, sut_uid, sut_gid, trusted_git_mirror, Path(policy['synthetic_root_path']), policy['git_test_remote_url'], policy['sut_components_sha256'], policy['sut_launch_mode']



def build_p01_test_run(*, pids, codes, start_ticks, argv, raw, workspace, git_sha,
                       collector_sha, trusted_git_mirror, trusted_remote_url):
    """Pure runner metadata assembly, with independently signed test remote URL.

    No data is read from SUT's output and no acceptance result is generated here.
    """
    return TestRun(pid=pids[-1],returncode=codes[-1],
                   command_digest=hashlib.sha256(_canonical(argv)).hexdigest(),
                   fixture_digest=hashlib.sha256(_canonical(raw)).hexdigest(),
                   workspace=workspace,git_sha=git_sha,run_id=str(uuid.uuid4()),
                   process_start_ticks=start_ticks,process_pids=tuple(pids),
                   returncodes=tuple(codes),collector_sha256=collector_sha,
                   trusted_remote_repo=trusted_git_mirror,trusted_remote_url=trusted_remote_url)

@pytest.mark.parametrize('ac_id,case', TEST_CASES,
                         ids=[f'{ac}:{s["scenario_id"]}' for ac,s in TEST_CASES])
def test_p01_normative_acceptance(approved_test_subprocess, ac_id, case):
    argv, git_sha, collector, collector_sha, witness_key, sut_uid, sut_gid, trusted_git_mirror, synthetic_root, trusted_remote_url, approved_components, approved_launch_mode = approved_test_subprocess
    with tempfile.TemporaryDirectory(prefix='aio-p01-synthetic-') as scratch:
        scratch_path = Path(scratch)
        workspace = scratch_path / 'workspace'
        workspace.mkdir(mode=0o700)
        # Only the separate, least-privileged SUT user can write the SUT sandbox;
        # the root/runner-owned trusted_evidence sibling is not exposed to it.
        try:
            scratch_path.chmod(0o711)
            os.chown(workspace, sut_uid, sut_gid)
        except OSError:
            pytest.fail('NOT_CHECKED: cannot isolate approved SUT workspace',pytrace=False)
        env = {'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'AIO_TEST_ONLY':'1',
               'HOME':str(workspace), 'TMPDIR':str(workspace)}
        raw = case['synthetic_input']
        try:
            synthetic_evidence = materialize_synthetic_objects(raw,workspace,sut_uid=sut_uid,sut_gid=sut_gid)
            require_sut_synthetic_evidence_access(synthetic_evidence,sut_uid=sut_uid,sut_gid=sut_gid)
        except ProbeError as exc:
            pytest.fail(str(exc),pytrace=False)
        # Admission requires independently provisioned OS sentinels. A declared
        # synthetic generator alone is never evidence that the file exists.
        if raw.get('require_preexisting_test_sentinel'):
            try:
                require_preexisting_synthetic_sentinel(raw, trusted_root=synthetic_root)
            except ProbeError as exc:
                pytest.fail(str(exc),pytrace=False)
        # NEW-D5-017: a repeated registration is two actual subprocess calls
        # operating on the SAME persisted workspace, not a fictitious count.
        steps = raw.get('sequence') or [raw]
        pids, codes, start_ticks = [], [], 0
        # Each Popen executes pinned file descriptors, never pathnames
        # subject to symlink swap or post-check rename.
        with open_pinned_launch(argv,approved_components,launch_mode=approved_launch_mode) as pinned:
            for step in steps:
                fixture = workspace / f'input-{len(pids)}.json'
                fixture.write_bytes(_canonical(step))
                process = subprocess.Popen(list(pinned.argv) + [str(fixture)],
                                           executable=pinned.executable,pass_fds=pinned.pass_fds,
                                           cwd=workspace, env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           user=sut_uid, group=sut_gid, extra_groups=[],
                                           start_new_session=True)
                try:
                    start_ticks = _start_ticks(process.pid)
                    status = Path(f'/proc/{process.pid}/status').read_text()
                    try:
                        verify_sut_proc_identity(status, sut_uid=sut_uid, sut_gid=sut_gid, runner_uid=os.geteuid())
                    except ProbeError as exc:
                        process.kill(); process.wait()
                        pytest.fail(str(exc),pytrace=False)
                    process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    pytest.fail('NOT_CHECKED: P01 synthetic subprocess timed out', pytrace=False)
                pids.append(process.pid)
                codes.append(process.returncode)
        run = build_p01_test_run(pids=pids,codes=codes,start_ticks=start_ticks,argv=argv,
                                  raw=raw,workspace=workspace,git_sha=git_sha,
                                  collector_sha=collector_sha,trusted_git_mirror=trusted_git_mirror,
                                  trusted_remote_url=trusted_remote_url)
        # NINTH-D5-042: every one of the 63 acceptance scenarios requires an
        # independently authenticated complete execve + load closure witness,
        # regardless of whether the per-AC JSON lists subprocess_audit.
        sources = list(dict.fromkeys([p['source'] for p in case['independent_proofs']] + ['execve_trace']))
        required_case = {**case, 'independent_proofs': [*case['independent_proofs'],
                              *([] if 'execve_trace' in [p['source'] for p in case['independent_proofs']]
                                else [{'source':'execve_trace','required':True}])]}
        try:
            evidence = collect_trusted_evidence(synthetic_input=raw, required_sources=sources,
                                                run=run, collector_file=collector,
                                                collector_sha256=collector_sha, witness_key=witness_key, sut_uid=sut_uid)
            verify_independent_proofs(required_case, {}, evidence, run,
                                      trusted_witness_key=witness_key,
                                      expected_git_sha=git_sha, expected_command_digest=run.command_digest,
                                      expected_collector_sha256=collector_sha)
            verify_execution_closure(evidence['execve_trace'].captures,
                                     approved_components_sha256=approved_components,
                                     process_pids=tuple(pids))
        except ProbeError as exc:
            pytest.fail(str(exc), pytrace=False)
