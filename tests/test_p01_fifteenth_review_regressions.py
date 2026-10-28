"""Fifteenth review FIFTEENTH-D5-054/055/056, synthetic-only negative tests."""
import ast
import copy
from pathlib import Path

import pytest
from p01_oqa_attestation import OQAttestationError, _canon, verify_oqa_receipt
from test_p01_twelfth_review_regressions import (
    signed_case, synthetic_response, TEST_KERNEL_AUDIT_SIGNER,
)


def _check(p, request, attestation, attester):
    envelope = synthetic_response(attestation, attester)
    return verify_oqa_receipt(envelope, p, request,
                              attester_key=attester.public_key(),
                              kernel_audit_key=TEST_KERNEL_AUDIT_SIGNER.public_key())


def _resign_kernel_audit(attestation):
    record = attestation['__synthetic_kernel_audit_envelope']['receipt']
    attestation['__synthetic_kernel_audit_envelope']['signature'] = (
        TEST_KERNEL_AUDIT_SIGNER.sign(_canon(record)).hex()
    )


def test_054_full_acceptance_file_compiles_and_defers_ac_until_after_closure():
    """Works on exact checkout; NEVER use a reconstructed acceptance file as PASS."""
    path = Path(__file__).with_name('test_p01_acceptance.py')
    if not path.is_file():
        pytest.skip('exact-SHA acceptance source unavailable in isolated source subset')
    raw = path.read_bytes()
    ast.parse(raw.decode('utf-8'), filename=str(path))
    assert b'\\n' not in raw, 'backslash-n escapes in acceptance driver source'
    source = raw.decode('utf-8')
    start = source.index('observations=verify_independent_proofs(')
    gate = source.index('verify_execution_closure(', start)
    last = source.index('verify_normative_measurements(required_case,observations,run)', gate)
    assert 'evaluate_expected=False' in source[start:gate]
    assert start < gate < last


def test_055_normal_two_source_kernel_capture_window_accepted():
    p, request, attestation, key = signed_case()
    events = attestation['__synthetic_kernel_audit_envelope']['receipt']['kernel_syscall_events']
    assert len({e['timestamp_monotonic_ns'] for e in events}) >= 2
    assert _check(p, request, attestation, key)


@pytest.mark.parametrize('window', ['stops_before_last','starts_after_first','starts_after_all'])
def test_055_kernel_events_outside_audit_capture_window_are_denied(window):
    p, request, attestation, key = signed_case()
    audit = attestation['__synthetic_kernel_audit_envelope']['receipt']
    times = [e['timestamp_monotonic_ns'] for e in audit['kernel_syscall_events']]
    if window == 'stops_before_last':
        audit['capture_stopped_ns'] = min(times)
    elif window == 'starts_after_first':
        audit['capture_started_ns'] = max(times)
    else:
        audit['capture_started_ns'] = max(times) + 1
    assert audit['capture_started_ns'] <= audit['capture_stopped_ns']
    _resign_kernel_audit(attestation)
    with pytest.raises(OQAttestationError, match='NOT_CHECKED'):
        _check(p, request, attestation, key)


@pytest.mark.parametrize('loss_counter',[False,0.0,-1,1,None,'0',True])
def test_056_noninteger_or_nonzero_kernel_event_losses_are_denied(loss_counter):
    p, request, attestation, key = signed_case()
    attestation['__synthetic_kernel_audit_envelope']['receipt']['event_loss_count'] = loss_counter
    _resign_kernel_audit(attestation)
    with pytest.raises(OQAttestationError, match='NOT_CHECKED'):
        _check(p, request, attestation, key)


def test_056_missing_kernel_loss_counter_is_denied():
    p, request, attestation, key = signed_case()
    attestation['__synthetic_kernel_audit_envelope']['receipt'].pop('event_loss_count')
    _resign_kernel_audit(attestation)
    with pytest.raises(OQAttestationError, match='NOT_CHECKED'):
        _check(p, request, attestation, key)


def test_055_primary_and_kernel_events_have_distinct_timestamps_in_positive_fixture():
    p, request, attestation, key = signed_case()
    audit = attestation['__synthetic_kernel_audit_envelope']['receipt']
    timestamps = [e['timestamp_monotonic_ns'] for e in audit['kernel_syscall_events']]
    assert len(set(timestamps)) >= 2
    assert audit['capture_started_ns'] <= min(timestamps)
    assert max(timestamps) <= audit['capture_stopped_ns']
    assert _check(p, request, attestation, key)
