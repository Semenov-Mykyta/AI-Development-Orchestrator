"""P01 pre-implementation D5 test oracle. Never derives PASS from SUT reports.

Accepted execution is a real isolated test-only subprocess plus independently
witnessed effects. The OS/CI/Git-specific witness collectors do NOT yet exist;
therefore the acceptance suite remains NOT_CHECKED until they are reviewed and
wired to a real P01 implementation in an OQ-09/A sandbox. This is intentional.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

import pytest
from p01_probe import ProbeError, TestRun, verify_independent_proofs, verify_normative_expectations

ORACLE = Path(__file__).resolve().parent / 'fixtures' / 'p01' / 'P01_ORACLES.json'
ITEMS = json.loads(ORACLE.read_text(encoding='utf-8'))['items']
verify_normative_expectations(ITEMS)
TEST_CASES = [(r['ac_id'], s) for r in ITEMS if r['auto_test_required'] for s in r['scenarios']]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf8')


@pytest.fixture(scope='session')
def approved_test_subprocess():
    """Command to exercise real P01 SUT; not an observer returning expected JSON."""
    command = os.environ.get('AIO_P01_SUT_COMMAND')
    if not command:
        pytest.fail('NOT_CHECKED: no real P01 command wired to OQ-09/A isolated runner', pytrace=False)
    argv = shlex.split(command)
    if not argv or not Path(argv[0]).is_absolute():
        pytest.fail('NOT_CHECKED: SUT binary must be an explicitly approved absolute executable', pytrace=False)
    if not Path(argv[0]).is_file():
        pytest.fail('NOT_CHECKED: approved SUT binary does not exist', pytrace=False)
    return argv


@pytest.mark.parametrize('ac_id,case', TEST_CASES,
                         ids=[f'{ac}:{s["scenario_id"]}' for ac,s in TEST_CASES])
def test_p01_normative_acceptance(approved_test_subprocess, ac_id, case):
    """Request exercise -> independent probes -> assert actual effects (never stdout)."""
    with tempfile.TemporaryDirectory(prefix='aio-p01-synthetic-') as scratch:
        scratch_path = Path(scratch)
        workspace = scratch_path / 'workspace'
        workspace.mkdir()
        fixture_path = workspace / 'input.json'
        fixture_path.write_bytes(canonical(case['synthetic_input']))
        # Do not inherit production or supervisor credentials. Minimal, static env.
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'AIO_TEST_ONLY': '1',
               'HOME': str(workspace), 'TMPDIR': str(workspace)}
        process = subprocess.Popen(approved_test_subprocess + [str(fixture_path)],
                                   cwd=workspace, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            _out, _err = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            pytest.fail("NOT_CHECKED: P01 synthetic SUT process timed out", pytrace=False)
        run = TestRun(pid=process.pid,
                      returncode=process.returncode,
                      command_digest=hashlib.sha256(canonical(approved_test_subprocess)).hexdigest(),
                      fixture_digest=hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
                      workspace=workspace)
        # No trustworthy witness collector is yet implemented or authorized.
        # Never synthesize evidence by copying the JSON oracle, stdout or stderr.
        try:
            verify_independent_proofs(case, {}, {}, run)
        except ProbeError as exc:
            pytest.fail(str(exc), pytrace=False)
