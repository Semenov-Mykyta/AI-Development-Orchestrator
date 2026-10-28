"""Unit tests of verifier, NOT independent SUT acceptance tests.

All constructed witness bytes are synthetic. These check crypto/provenance
validation correctness, not OS/process authenticity (runner-only responsibility).
"""
import hashlib
from pathlib import Path

import pytest
from p01_probe import (IndependentProof, ProbeError, TestRun, _canonical,
                       _evidence_mac, _run_identity, verify_independent_proofs,
                       collect_trusted_evidence)

KEY=b'local-only-ephemeral-independent-test-key-1234'
COLLECTOR_SHA='b'*64
SHA='a'*40
FIXTURE={'operation':'policy_gate_evaluate','proposed_action':{'action':'skip_required_test'}}
CASE={'synthetic_input':FIXTURE,
      'expected_observations':{'allowed':False,'side_effects':0},
      'independent_proofs':[{'source':'filesystem_snapshot','required':True},
                            {'source':'subprocess_audit','required':True}]}


def params(run, key=KEY):
    return {'trusted_witness_key':key,'expected_git_sha':SHA,
            'expected_command_digest':run.command_digest,
            'expected_collector_sha256':run.collector_sha256}


def setup_probe(tmp_path, *, corrupt=False):
    workspace=tmp_path/'workspace';workspace.mkdir()
    directory=tmp_path/'trusted_evidence';directory.mkdir()
    run=TestRun(pid=4817,returncode=0,command_digest='1'*64,
                fixture_digest=hashlib.sha256(_canonical(FIXTURE)).hexdigest(), workspace=workspace,
                git_sha=SHA,run_id='synthetic-verifier-unit-run-01',process_start_ticks=123456,
                process_pids=(4817,),returncodes=(0,),collector_sha256=COLLECTOR_SHA)
    captures={'filesystem_snapshot':{'side_effects':0}, 'subprocess_audit':{'allowed':False}}
    proofs={}
    for source, measurement in captures.items():
        path=directory/f'{source}.json'
        path.write_bytes(_canonical({'schema':'aio.p01.independent_witness.v1',
                                     'source':source,'run':_run_identity(run),'measurement':measurement}))
        unsigned=IndependentProof(source=source,path=path,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                  captures=measurement,run_pid=run.pid,fixture_digest=run.fixture_digest,
                                  witness_mac='',run_id=run.run_id,git_sha=run.git_sha,
                                  run_command_digest=run.command_digest,run_returncode=run.returncode,
                                  process_start_ticks=run.process_start_ticks)
        proofs[source]=IndependentProof(**{**vars(unsigned),'witness_mac':_evidence_mac(KEY,unsigned)})
    if corrupt:
        proofs['filesystem_snapshot'].path.write_text('tampered',encoding='utf8')
    return run,proofs


def test_self_report_without_external_evidence_is_not_pass(tmp_path):
    run,_=setup_probe(tmp_path)
    with pytest.raises(ProbeError,match='witness missing'):
        verify_independent_proofs(CASE,{'allowed':False,'side_effects':0,'evidence_ref':'self.txt'}, {},run,**params(run))


def test_synthetic_unit_witnesses_have_matching_run(tmp_path):
    run,proofs=setup_probe(tmp_path)
    actual=verify_independent_proofs(CASE,{'allowed':True,'side_effects':9},proofs,run,**params(run))
    assert actual==CASE['expected_observations']


def test_evidence_tamper_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path,corrupt=True)
    with pytest.raises(ProbeError,match='mutated'):
        verify_independent_proofs(CASE,{},proofs,run,**params(run))


def test_evidence_wrong_pid_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path)
    altered=TestRun(**{**vars(run),'pid':run.pid+1,'process_pids':(run.pid+1,)})
    with pytest.raises(ProbeError,match='wrong execution'):
        verify_independent_proofs(CASE,{},proofs,altered,**params(altered))


def test_untrusted_evidence_signature_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path)
    with pytest.raises(ProbeError,match='not captured by trusted runner'):
        verify_independent_proofs(CASE,{},proofs,run,**params(run,b'wrong-test-key'*3))


def test_no_witness_key_denies_even_valid_artifacts(tmp_path):
    run,proofs=setup_probe(tmp_path)
    with pytest.raises(ProbeError,match='witness authority absent'):
        verify_independent_proofs(CASE,{},proofs,run,**params(run,None))


def test_wrong_git_sha_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path)
    with pytest.raises(ProbeError,match='Git HEAD SHA'):
        verify_independent_proofs(CASE,{},proofs,run,
                                  **{**params(run),'expected_git_sha':'b'*40})


def test_wrong_command_digest_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path)
    with pytest.raises(ProbeError,match='command'):
        verify_independent_proofs(CASE,{},proofs,run,
                                  **{**params(run),'expected_command_digest':'b'*64})


def test_replay_from_another_run_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path)
    newer=TestRun(**{**vars(run),'run_id':'different-run-id'})
    with pytest.raises(ProbeError,match='wrong execution'):
        verify_independent_proofs(CASE,{},proofs,newer,**params(newer))


def test_changed_returncode_even_with_original_mac_is_rejected(tmp_path):
    run,proofs=setup_probe(tmp_path)
    newer=TestRun(**{**vars(run),'returncode':9,'returncodes':(9,)})
    with pytest.raises(ProbeError,match='provenance mismatch'):
        verify_independent_proofs(CASE,{},proofs,newer,**params(newer))


def test_real_subprocess_and_external_fs_collector_positive_and_negative(tmp_path, monkeypatch):
    """Plumbing smoke test: real child makes a file, independent plugin stats it.

    NOT a P01/OS-security acceptance PASS. This is a self-contained unit test.
    """
    import subprocess
    import sys
    from p01_probe import _sha256

    scratch=tmp_path/'scratch';scratch.mkdir()
    workspace=scratch/'workspace';workspace.mkdir()
    # This dedicated subprocess never obtains the witness key or external plugin.
    process=subprocess.Popen([sys.executable,'-c',
                              'from pathlib import Path;Path("synthetic_record").write_text("x")'],
                             cwd=workspace, env={'PATH':'/usr/bin:/bin'})
    from test_p01_acceptance import _start_ticks
    ticks=_start_ticks(process.pid)
    process.communicate(timeout=5)
    fixture={'operation':'touch_test_file'}
    run=TestRun(pid=process.pid,returncode=process.returncode,command_digest='c'*64,
                fixture_digest=_sha256(_canonical(fixture)),workspace=workspace,git_sha=SHA,
                run_id='runner-issued-positive-smoke',process_start_ticks=ticks,
                process_pids=(process.pid,),returncodes=(process.returncode,),
                collector_sha256='')
    plugin=tmp_path/'test_collector.py'
    plugin.write_text('''\ndef collect(*, synthetic_input, run, required_sources):\n    from pathlib import Path\n    return {'filesystem_snapshot':{'actual_file_created':(run.workspace/'synthetic_record').read_text()=='x'}}\n''',encoding='utf8')
    plugin.chmod(0o600)
    from dataclasses import replace
    run=replace(run,collector_sha256=_sha256(plugin.read_bytes()))
    # Pure unit-only seam: mock *authorization* of the temporary collector;
    # dedicated negative tests cover rejection by the production trust boundary.
    # A local tmp_path collector must NEVER be accepted by real root-owned loader.
    import importlib.util
    from p01_probe import ProbeError
    spec=importlib.util.spec_from_file_location('unit_only_fs_collector',plugin)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    monkeypatch.setattr('p01_probe._load_pinned_collector',lambda *a, **k: module.collect)
    evidence=collect_trusted_evidence(synthetic_input=fixture,required_sources=['filesystem_snapshot'],
                                      run=run,collector_file=plugin,collector_sha256=_sha256(plugin.read_bytes()),
                                      witness_key=KEY)
    test_case={'synthetic_input':fixture,'independent_proofs':[{'source':'filesystem_snapshot'}],
               'expected_observations':{'actual_file_created':True}}
    assert verify_independent_proofs(test_case, {'actual_file_created':False}, evidence, run, **params(run))['actual_file_created']
    neg={'synthetic_input':fixture,'independent_proofs':[{'source':'filesystem_snapshot'}],
         'expected_observations':{'actual_file_created':False}}
    with pytest.raises(ProbeError,match='FAIL'):
        verify_independent_proofs(neg,{},evidence,run,**params(run))
