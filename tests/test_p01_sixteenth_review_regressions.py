"""Regression tests for SIXTEENTH-D5-057/058: synthetic Ed25519 receipts only.

Use the actual verify_oqa_receipt. A correctly signed malformed receipt MUST
fail closed as OQAttestationError('NOT_CHECKED: ...'), never a raw TypeError.
"""
from copy import deepcopy
import pytest

from p01_oqa_attestation import OQAttestationError, verify_oqa_receipt
from test_p01_twelfth_review_regressions import (
    TEST_KERNEL_AUDIT_SIGNER, signed_case, synthetic_response,
)


def _run(p, q, r, key):
    return verify_oqa_receipt(synthetic_response(r, key), p, q,
                              attester_key=key.public_key(),
                              kernel_audit_key=TEST_KERNEL_AUDIT_SIGNER.public_key())


def test_057_exact_zero_brokers_is_allowed_on_valid_synthetic_receipt():
    p, q, r, key = signed_case()
    assert type(r['signer_deployment']['unaudited_signing_brokers']) is int
    assert r['signer_deployment']['unaudited_signing_brokers'] == 0
    assert _run(p, q, r, key) is True


@pytest.mark.parametrize('wrong_count', [False, 0.0, True, -1, 1, None, '0', [], {}],
                         ids=['bool_false','float_zero','bool_true','negative','positive',
                              'null','string','list','dict'])
def test_057_broker_count_must_be_exact_integer_zero(wrong_count):
    p, q, r, key = signed_case()
    r['signer_deployment']['unaudited_signing_brokers'] = wrong_count
    with pytest.raises(OQAttestationError, match='NOT_CHECKED'):
        _run(p, q, r, key)  # synthetic attester signature freshly generated


def test_057_missing_broker_counter_fails_closed():
    p, q, r, key = signed_case()
    del r['signer_deployment']['unaudited_signing_brokers']
    with pytest.raises(OQAttestationError, match='NOT_CHECKED'):
        _run(p, q, r, key)


@pytest.mark.parametrize('broken_interfaces', [
    [{'target': []}], [{'target': {'socket': '/tmp/malicious'}}],
    [{'target': None}], [{'target': 123}], [{'target': ''}],
    [{'target': '/signed/socket'}, {'target': '/signed/socket'}],
    [42], ['not-a-dict'], {}, None, [],
], ids=['target_list','target_dict','target_null','target_integer','target_empty',
         'duplicate_targets','interface_integer','interface_string',
         'interfaces_dict','interfaces_null','interfaces_empty'])
def test_058_invalid_interface_endpoints_fail_closed(broken_interfaces):
    p, q, r, key = signed_case()
    r['signer_deployment']['signing_interfaces'] = deepcopy(broken_interfaces)
    with pytest.raises(OQAttestationError, match='NOT_CHECKED'):
        _run(p, q, r, key)


@pytest.mark.parametrize('bad_endpoints', [
    [{'target': '/signed/socket'}], [[]], [None], [7], [''],
    ['/signed/socket', '/signed/socket'], 'not-a-list', None,
], ids=['dict','list','null','integer','empty','duplicate','string','missing'])
def test_058_invalid_discovered_audit_endpoints_fail_closed(bad_endpoints):
    p, q, r, key = signed_case()
    r['__synthetic_kernel_audit_envelope']['receipt']['discovered_signing_endpoints'] = deepcopy(bad_endpoints)
    audit = r['__synthetic_kernel_audit_envelope']
    audit['signature'] = TEST_KERNEL_AUDIT_SIGNER.sign(
        __import__('p01_oqa_attestation')._canon(audit['receipt'])
    ).hex()
    with pytest.raises(OQAttestationError, match='NOT_CHECKED'):
        _run(p, q, r, key)  # both synthetic keys sign freshly
