"""NINETEENTH-D5-063/064: exact-type execution identity and malformed JSON root.

All Ed25519 and HMAC keys are synthetic and must not be treated as real OQ-09/A.
"""
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from p01_probe import (ProbeError, IndependentProof, _canonical, _sha256,
                       _evidence_mac, verify_independent_proofs)
from p01_oqa_attestation import verify_readonly_observer_measurements
from test_p01_eighteenth_review_regressions import (
    KEY, make_run, signed_capture, proof_for,
)


def checked_fixture(tmp_path, *, modified_run=None, raw_changes=None, proof_changes=None, root=None):
    run, fixture=make_run(tmp_path)
    if modified_run:
        run=replace(run, **modified_run)
    signer=Ed25519PrivateKey.generate()
    source='sqlite_snapshot'
    capture=signed_capture(source, {'admitted': True}, signer)
    proof=proof_for(tmp_path,run,source,capture,capture)
    if raw_changes is not None or root is not None:
        doc=json.loads(proof.path.read_bytes())
        if root is not None:
            doc=root
        else:
            doc['run'].update(raw_changes)
        proof.path.write_bytes(_canonical(doc))
        proof=replace(proof,sha256=_sha256(proof.path.read_bytes()))
    if proof_changes:
        proof=replace(proof,**proof_changes)
    proof=replace(proof,witness_mac='')
    proof=replace(proof,witness_mac=_evidence_mac(KEY,proof))
    evidence={source:proof}
    assert verify_readonly_observer_measurements(evidence,
        observer_key=signer.public_key(),observer_id='synthetic-observer',
        run_id=run.run_id,git_sha=run.git_sha,command_digest=run.command_digest)
    case={'synthetic_input':fixture,
          'independent_proofs':[{'source':source,'required':True}],
          'expected_observations':{'admitted':True}}
    return case,evidence,run


def verify(case,evidence,run):
    return verify_independent_proofs(case,{},evidence,run,
       trusted_witness_key=KEY,expected_git_sha=run.git_sha,
       expected_command_digest=run.command_digest,
       expected_collector_sha256=run.collector_sha256)


@pytest.mark.parametrize('mutation',[
    {'pid':1527.0}, {'returncode':False}, {'process_start_ticks':17.0},
    {'process_pids':[1527.0]}, {'returncodes':[False]},
    {'returncodes':[0.0]}, {'process_pids':[1527.0]},
],ids=['raw-pid-float','raw-returncode-false','raw-start-ticks-float',
        'raw-pid-list-float','raw-returncodes-bool','raw-returncodes-float',
        'raw-process-list-float'])
def test_063_authenticated_raw_run_metadata_type_mismatch(tmp_path,mutation):
    case,evidence,run=checked_fixture(tmp_path,raw_changes=mutation)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify(case,evidence,run)


@pytest.mark.parametrize('mutation',[
    {'run_pid':1527.0},{'run_returncode':False},
    {'process_start_ticks':17.0},{'process_start_ticks':True},
],ids=['proof-pid-float','proof-returncode-false','proof-ticks-float','proof-ticks-true'])
def test_063_authenticated_proof_metadata_type_mismatch(tmp_path,mutation):
    case,evidence,run=checked_fixture(tmp_path,proof_changes=mutation)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify(case,evidence,run)


@pytest.mark.parametrize('mutation',[
    {'returncode':False},{'process_start_ticks':True},
    {'returncodes':(False,)},{'process_pids':(1527.0,)},
    {'pid':True,'process_pids':(1,)},
],ids=['run-returncode-false','run-start-ticks-true','run-returncodes-false',
        'run-process-pids-float','run-pid-true'])
def test_063_runner_identity_type_admission(tmp_path,mutation):
    case,evidence,run=checked_fixture(tmp_path,modified_run=mutation)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify(case,evidence,run)


@pytest.mark.parametrize('root',[
    [], [1], 'invalid-root', 0, True, False, [None],
],ids=['empty-array','array-of-number','string','number','true','false','null-array'])
def test_064_malformed_top_level_witness_returns_not_checked(tmp_path,root):
    case,evidence,run=checked_fixture(tmp_path,root=root)
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify(case,evidence,run)


def test_064_null_root_must_not_raise_attribute_error(tmp_path):
    case,evidence,run=checked_fixture(tmp_path)
    proof=evidence['sqlite_snapshot']
    proof.path.write_text('null')
    proof=replace(proof,sha256=_sha256(proof.path.read_bytes()),witness_mac='')
    proof=replace(proof,witness_mac=_evidence_mac(KEY,proof))
    with pytest.raises(ProbeError,match='NOT_CHECKED'):
        verify(case,{'sqlite_snapshot':proof},run)


def test_063_064_valid_synthetic_witness_still_passes(tmp_path):
    case,evidence,run=checked_fixture(tmp_path)
    assert verify(case,evidence,run)=={'admitted':True}
