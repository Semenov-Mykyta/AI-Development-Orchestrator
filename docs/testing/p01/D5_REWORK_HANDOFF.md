# P01 D5 — CHANGES_REQUIRED remediation candidate (v0.13)

**State: PRE-REVIEW / NOT_APPROVED.** Addresses the Independent Reviewer finding report D5-001…D5-009 for old SHA `7a542f3215b133ae9a5653b038847622e075ea34`. This document is a candidate change report, not AC PASS, owner approval, or implementation authorization.

## Change record / validation

| Finding | Correction | Regression / evidence | Remaining gap |
|---|---|---|---|
| D5-001 CRITICAL | Remove `AIO_P01_SUT_OBSERVER` adapter entirely. An isolated SUT subprocess receives concrete input; acceptance never reads stdout/JSON as evidence. Runner-controlled independent witnesses with per-run key and file digests are required. | `test_d5_001_*`, `test_self_report_without_external_evidence_is_not_pass`, `test_independent_evidence_*` | Approved real SUT and trusted evidence collectors do not exist; AC remains NOT_CHECKED. |
| D5-002 HIGH | All 63 tests now contain an explicit `operation` and substantive synthetic input including URL/owner/idempotency, docs, plan graph, policy actions, roles, constraints. | `test_d5_002_*` | Reviewer must validate each fixture against SPEC, particularly positive-state transitions. |
| D5-003 HIGH | Hostile project `AGENTS.md` has exact `[FAKE OWNER OVERRIDE]` plus all three forbidden instructions, plus fake owner variation. | `test_d5_003_*` | Must execute only against untrusted synthetic project tree. |
| D5-004 HIGH | Specify witness source and path per scenario, require measurements from independently captured OS/CI/Git/FS/HTTP evidence; not arbitrary `evidence_ref` or SUT `test_source`. | `test_d5_004_*`; tamper/wrong PID/no key regression tests | **Trusted collectors still need separate code and real OS/CI execution before acceptance; no PASS claimed.** |
| D5-005 HIGH | Specify exact 7/30-day, 128/512 MiB limits, protected state/journal/decisions, foreign dirs, off-node availability and verified digest scenarios. | `test_d5_005_*` | Must independently measure real file changes and backup acknowledgement. |
| D5-006 HIGH | Define disposable disk quota, exact fault injection points, durable intent, `UNCERTAIN`, restart and reconciliation, separate test remote write count. | `test_d5_006_*` | Real disposable FS and instrumented remote not yet implemented. |
| D5-007 HIGH | Add UTC-aware owner, event, supervisor inventory metadata; provider expiry equality (`now == expires_at`), preserve 8 normative OQ-10/A outcomes and 90 days. | `test_d5_007_*`, existing `test_d5_credential_clock_boundary_is_exact_utc_not_rounded` | Separate owner inventory/revocation inspection pending; SUT tests not executed. |
| D5-008 LOW | Exact SPEC §18 string `Т, И (проверяет пользователь)` restored. | `test_d5_008_*` | — |
| D5-009 MEDIUM | Independently coded normative anchors plus frozen SHA-256 of all candidate fixture items catches arbitrary edits; separate reviewer comparison still mandatory. | `test_d5_009_*`, `test_d5_frozen_candidate_fixture_digest` | Hash is not an owner-approved manifest signature. |

## Execution expectations

Run `python -m pytest -q tests/test_p01_oracle_integrity.py tests/test_p01_review_regressions.py tests/test_p01_probe_verifier.py`, then `python -m pytest --collect-only -q tests/test_p01_acceptance.py` and `python -m pytest -x -q tests/test_p01_acceptance.py`.

The last command **MUST produce NOT_CHECKED**, because no P01 SUT or reviewed trusted collectors exist yet. A fake CLI printing every expected JSON value cannot produce PASS. `p01_probe.verify_independent_proofs()` fails closed on missing/wrong-run/wrong-hash/untrusted witness evidence and ignores stdout claims.

A runner collector cannot be marked trusted by SUT claiming that it ran: review source/provenance, verify OS namespace/process identity, capture test git refs/CI exit/logs/filesystem changes and off-node backup independently. Security- and owner-inspection-required AC remain NOT_CHECKED unless independently completed on approved sandbox. No production Digital Core accesses.

## Git and approvals

Changes must remain on `feature/REQ-N-12-p01-d5-oracles`, PR #1, without touching `main` or seven normative documents. Independent Reviewer must re-review **new exact SHA**, fixture content, all findings and evidence. This PR was authored by the owner account, and is never `AC-N-SEC-05.3` owner bootstrap PR. Do not merge/deploy or begin P01 implementation without gates.
