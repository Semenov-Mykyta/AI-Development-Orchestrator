"""Test-only independent evidence verifier for P01 D5 (NOT shipping SUT API).

Security invariant: result text emitted by a tested subprocess is *never* an
acceptance oracle. The isolated harness must collect authoritative measurements
from independent OS/CI/git/FS/loopback services before declaring an AC observed.
No collector for a source => NOT_CHECKED, never PASS.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProbeError(AssertionError):
    """Fail closed: missing or unauthenticated evidence is NOT_CHECKED."""


_ALLOWED_WITNESS_SOURCES = frozenset({
    'sqlite_snapshot', 'subprocess_audit', 'git_test_remote',
    'filesystem_snapshot', 'document_digest', 'http_test_server',
    'offnode_stub', 'controlled_disk_fault', 'durable_journal',
    'git_history_refs', 'secret_scanner_report', 'ci_runner_exit',
    'redacted_error_log', 'os_syscall_trace',
    'supervisor_inventory_metadata', 'outbound_call_counter',
})

# Normative anchors independently coded from SPEC (not read from the fixture's
# expected_observations). Reviewer must validate this list and its boundaries.
_CRITICAL_EXPECTATIONS = {
    ('AC-F-01.1', 'accepted-owner-registration', 'status'): 'PENDING_PRECHECK',
    ('AC-F-02.1', 'non-allowlisted-url', 'reason'): 'REPO_NOT_ALLOWED',
    ('AC-F-04.1', 'markdown-APPROVED-no-trust-anchor', 'worker_launches'): 0,
    ('AC-N-12.1', 'skip-mandatory-test', 'allowed'): False,
    ('AC-N-12.1', 'disable-secret-scanning', 'allowed'): False,
    ('AC-N-12.1', 'change-approved-AC-oracle', 'allowed'): False,
    ('AC-N-12.1', 'exceed-resource-cap', 'allowed'): False,
    ('AC-N-12.1', 'unauthorized-merge', 'allowed'): False,
    ('AC-ERR-03.2', 'full-fs-before-durable-intent', 'remote_write_calls'): 0,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'ack_calls'): 0,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'journal_state'): 'UNCERTAIN',
    ('AC-N-SEC-05.5', 'exactly-next-due', 'decision'): 'DENY',
    ('AC-N-SEC-05.5', 'before-due-valid-scope', 'decision'): 'ALLOW',
    ('AC-N-SEC-05.5', 'new-ref-valid-scope', 'decision'): 'ALLOW',
    ('AC-N-SEC-05.5', 'provider-expiry-comes-first', 'decision'): 'DENY',
    ('AC-N-15.2', 'evidence-512MiB-without-offnode', 'reason'): 'ARTIFACT_QUOTA_BLOCKED',
}


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def verify_normative_expectations(items: list[dict[str, Any]]) -> None:
    for (ac, sid, key), required_value in _CRITICAL_EXPECTATIONS.items():
        rows = [r for r in items if r['ac_id'] == ac]
        if len(rows) != 1:
            raise ProbeError(f'NOT_CHECKED: normative AC missing/duplicated: {ac}')
        cases = [s for s in rows[0]['scenarios'] if s['scenario_id'] == sid]
        if len(cases) != 1 or cases[0]['expected_observations'].get(key) != required_value:
            raise ProbeError(f'NOT_CHECKED: mandatory normative expectation mismatch: {ac}/{sid}/{key}')
    for row in items:
        for case in row['scenarios']:
            if not case.get('synthetic_input', {}).get('operation'):
                raise ProbeError(f'NOT_CHECKED: missing operation: {row["ac_id"]}/{case["scenario_id"]}')
            expected = case.get('expected_observations')
            if not isinstance(expected, dict) or not expected:
                raise ProbeError('NOT_CHECKED: no expected observations')


@dataclass(frozen=True)
class TestRun:
    __test__ = False
    """Created by pytest after it actually launches a child, not by child stdout."""
    pid: int
    returncode: int
    command_digest: str
    fixture_digest: str
    workspace: Path


@dataclass(frozen=True)
class IndependentProof:
    """External witness bytes saved outside SUT writable directories."""
    source: str
    path: Path
    sha256: str
    captures: dict[str, Any]
    run_pid: int
    fixture_digest: str
    witness_mac: str


def _evidence_mac(key: bytes, proof: IndependentProof) -> str:
    signed = [proof.source, str(proof.path), proof.sha256, proof.run_pid,
              proof.fixture_digest, proof.captures]
    return hmac.new(key, _canonical(signed), hashlib.sha256).hexdigest()


def verify_independent_proofs(
    case: dict[str, Any],
    reported_by_sut: dict[str, Any],
    evidence: dict[str, IndependentProof],
    run: TestRun | None,
    *,
    trusted_witness_key: bytes | None = None,
) -> dict[str, Any]:
    """Returns observations extracted ONLY from independently witnessed evidence.

    `reported_by_sut` is deliberately IGNORED. The caller must create a
    TestRun via a real subprocess and IndependentProof objects from separately
    collected witness files, MAC-ed by the harness key never sent to the SUT.
    Returning `expected_observations`, `test_source`, or an arbitrary evidence_ref
    without witnesses cannot yield PASS.
    """
    if run is None or not isinstance(run, TestRun) or run.pid <= 0:
        raise ProbeError('NOT_CHECKED: actual subprocess PID missing')
    if not trusted_witness_key or len(trusted_witness_key) < 32:
        raise ProbeError('NOT_CHECKED: independent runner witness authority absent')
    actual_fixture_digest = hashlib.sha256(_canonical(case['synthetic_input'])).hexdigest()
    if run.fixture_digest != actual_fixture_digest:
        raise ProbeError('NOT_CHECKED: fixture digest mismatch')
    if not run.workspace.is_dir():
        raise ProbeError('NOT_CHECKED: sandbox workspace absent')
    observed: dict[str, Any] = {}
    for item in case['independent_proofs']:
        source = item['source']
        if source not in _ALLOWED_WITNESS_SOURCES:
            raise ProbeError(f'NOT_CHECKED: unsupported witness source: {source}')
        proof = evidence.get(source)
        if not isinstance(proof, IndependentProof) or proof.source != source:
            raise ProbeError(f'NOT_CHECKED: independent {source} witness missing')
        if proof.run_pid != run.pid or proof.fixture_digest != actual_fixture_digest:
            raise ProbeError(f'NOT_CHECKED: witness for wrong execution: {source}')
        if not proof.path.is_file() or not proof.path.is_relative_to(run.workspace.parent / 'trusted_evidence'):
            raise ProbeError(f'NOT_CHECKED: {source} witness outside trusted evidence directory')
        if not hmac.compare_digest(hashlib.sha256(proof.path.read_bytes()).hexdigest(), proof.sha256):
            raise ProbeError(f'NOT_CHECKED: {source} witness contents mutated')
        if not hmac.compare_digest(_evidence_mac(trusted_witness_key, proof), proof.witness_mac):
            raise ProbeError(f'NOT_CHECKED: {source} witness was not captured by trusted runner')
        if not proof.captures:
            raise ProbeError(f'NOT_CHECKED: {source} supplied no independent measurements')
        for k, value in proof.captures.items():
            if k in observed and observed[k] != value:
                raise ProbeError(f'NOT_CHECKED: inconsistent witness measurement: {k}')
            observed[k] = value
    # Avoid claiming acceptance from a descriptive reason/status in child stdout.
    for k, expected in case['expected_observations'].items():
        if k not in observed:
            raise ProbeError(f'NOT_CHECKED: no independent observation for {k}')
        if observed[k] != expected:
            raise ProbeError(f'FAIL: independent measurement differs for {k}: {observed[k]!r} != {expected!r}')
    return observed
