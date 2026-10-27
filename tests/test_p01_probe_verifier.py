"""Verify that a forged SUT report cannot manufacture external evidence (D5-001/004)."""
import hashlib
import json
from pathlib import Path

import pytest
from p01_probe import (IndependentProof, ProbeError, TestRun,
                        _canonical, _evidence_mac, verify_independent_proofs)

KEY=b'local-only-ephemeral-independent-test-key-1234'
FIXTURE={'operation':'policy_gate_evaluate','proposed_action':{'action':'skip_required_test'}}
CASE={
 'synthetic_input':FIXTURE,
 'expected_observations':{'allowed':False,'side_effects':0},
 'independent_proofs':[{'source':'filesystem_snapshot','required':True},
                       {'source':'subprocess_audit','required':True}]
}


def setup_probe(tmp_path, *, corrupt=False):
    workspace=tmp_path/'workspace'
    workspace.mkdir()
    evidence_dir=tmp_path/'trusted_evidence'
    evidence_dir.mkdir()
    run=TestRun(pid=4817,returncode=0,command_digest='1'*64,
                fixture_digest=hashlib.sha256(_canonical(FIXTURE)).hexdigest(), workspace=workspace)
    captures={'filesystem_snapshot':{'side_effects':0}, 'subprocess_audit':{'allowed':False}}
    proofs={}
    for source, measurement in captures.items():
        path=evidence_dir/f'{source}.json'
        path.write_bytes(_canonical({'measurement':measurement, 'source':source, 'run_pid':run.pid}))
        unsigned=IndependentProof(source=source,path=path,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                  captures=measurement,run_pid=run.pid,fixture_digest=run.fixture_digest,witness_mac='')
        proofs[source]=IndependentProof(**{**vars(unsigned),'witness_mac':_evidence_mac(KEY,unsigned)})
    if corrupt:
        proofs['filesystem_snapshot'].path.write_text('tampered',encoding='utf8')
    return run,proofs


def test_self_report_without_external_evidence_is_not_pass(tmp_path):
    run,_=setup_probe(tmp_path)
    with pytest.raises(ProbeError,match='witness missing'):
        verify_independent_proofs(CASE,{'allowed':False,'side_effects':0,'evidence_ref':'self.txt'}, {},run,
                                  trusted_witness_key=KEY)


def test_independent_witnesses_accepted_only_with_matching_run(tmp_path):
    run,proofs=setup_probe(tmp_path)
    actual=verify_independent_proofs(CASE,{'allowed':True,'side_effects':9},proofs,run,
                                      trusted_witness_key=KEY)
    assert actual==CASE['expected_observations']


def test_independent_evidence_tamper_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path,corrupt=True)
    with pytest.raises(ProbeError,match='mutated'):
        verify_independent_proofs(CASE,{},proofs,run,trusted_witness_key=KEY)


def test_independent_evidence_wrong_pid_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path)
    forged=TestRun(pid=run.pid+1,returncode=run.returncode,command_digest=run.command_digest,
                   fixture_digest=run.fixture_digest,workspace=run.workspace)
    with pytest.raises(ProbeError,match='wrong execution'):
        verify_independent_proofs(CASE,{},proofs,forged,trusted_witness_key=KEY)


def test_untrusted_evidence_signature_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path)
    with pytest.raises(ProbeError,match='not captured by trusted runner'):
        verify_independent_proofs(CASE,{},proofs,run,trusted_witness_key=b'wrong-test-key'*3)


def test_no_witness_key_denies_even_valid_artifacts(tmp_path):
    run,proofs=setup_probe(tmp_path)
    with pytest.raises(ProbeError,match='witness authority absent'):
        verify_independent_proofs(CASE,{},proofs,run,trusted_witness_key=None)
