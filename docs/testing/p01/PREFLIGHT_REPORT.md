# P01 preflight — read-only evidence and blockers

**[факт]** Date: 2026-10-27. Remote repo: `Semenov-Mykyta/AI-Development-Orchestrator`, base branch `main`, head `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8` from GitHub API. No remote write, branch, PR, implementation or merge was made.

**[факт]** The seven authoritative v0.13/APR-08-labelled documents are present at that exact commit. The observed SHA-256 are below. **These hashes are independently computed observations of GitHub bytes; they are NOT an independently authenticated owner-approved APR-08 manifest.** Original pre-APR8 ZIP digest `763b41df...` identifies an older content snapshot and cannot act as the SHA-256 of these seven amended files.

| Path | Observed SHA-256 (not owner-verified) |
|---|---|
| AGENTS.md | `aa3d67896a8b15dfdf9652b51881c2f69586ef10588587071636c7bc9ed9196e` |
| README.md | `43cc003edee4de9785c6951a47f035f4b631adabe9cabc94746a5f3c7fee14b6` |
| docs/spec/SPEC.md | `065009ca295c96a2af42c0bb82e8bf59bd4612a646e9d5224f43831472153ff2` |
| docs/spec/ARCHITECTURE.md | `eeac961b199bf1c6124ac7d981180c877495f324978e5c754e2f67a57d67fb94` |
| docs/spec/IMPLEMENTATION_PLAN.md | `0829f0f4fd023009966f712f6e330869cd62d7eef3f9e0422c6e6e6b19fa1d5c` |
| docs/spec/SECURITY.md | `384c907ca177351e158c0f4c18462c82b268900cf1e19ef720302e9eeaa55da0` |
| docs/spec/DATA_MODEL.md | `bd073a61919124202a3886253ab25e1f827ed30160a5449c277a6b6fe3ecea75` |

**[факт]** P01 plan JSON contains 18 unique REQ/ERR and 27 unique AC. SPEC §18 independently has the same 27 IDs; 22 methods T, 2 T+I, 2 I, 1 owner I. No discrepancies in IDs or method counts.

**[факт]** GitHub Ruleset 25956270 `AIO-Protect-Main` is active, target `~DEFAULT_BRANCH`, empty bypass list, `required_approving_review_count=1`, `dismiss_stale_reviews_on_push=true`, `deletion`, `non_fast_forward`; branch `main` is marked protected. Required CI status checks are **not configured**, and none are claimed PASS. `require_last_push_approval=false` on remote, not identical to the earlier screenshot impression; the approved mandatory review and exact-SHA owner evidence remain required regardless.

**[факт]** Remote Desktop Commander's read-only environment check on an online VPS showed Ubuntu 24.04, Python 3.12.3, Git 2.43.0, systemd 255 and cgroups v2; **this does not certify safe isolation** and does not authorize running P01 there. No production files or values of secrets were accessed. Local isolated artifact-preparation container is Debian 13 / Python 3.13.5, **not** approved OQ-09/A test environment.

**[не проверено]** No independent post-APR-08 owner manifest comparison, approved isolated test namespace/OS denied proof, pinned/hash-locked dependencies, scoped Developer Git identity, complete secret scan with approved pinned tool, owner inspections, Git working-tree status, or P01 application runtime. No remote Git write / CI checks were executed. All 27 AC = `NOT_CHECKED`.

## Material blockers

1. **Baseline admission** — approved manifest is expected **outside agent workspace**; the observed current SHA digests are not a proof of independent owner approval. `AC-F-04.1`, `AC-F-07.1`, `CON-01`. Stop implementation/runtime until verified.
2. **D5 review** — tests have not been independently approved in their own tests-only PR. `AGENTS.md D5`. Stop implementation until reviewer verdict.
3. **Git identity separation** — connected GitHub identity is `Semenov-Mykyta`, the repository owner; submitting P01 owner-inspection PR with the same author identity would prevent that owner identity from approving its own PR. `ARCHITECTURE.md §4.6`. Keep remote untouched; request separately scoped Developer identity when authoring a PR is possible.
4. **Isolated OS/CI profile not proven** — required OQ-09/A Ubuntu 24.04/Python 3.12 sandbox, synthetic OS denials and pinned scan/test dependencies are not ready. `DEP-01/02/05`, `AC-N-SEC-05.4`, `AC-N-SEC-03.1`, `AC-N-SEC-05.5`. No worker or synthetic mount/FS/network test on live production host.

**[PROP]** Choose a distinct scoped Developer GitHub actor to create the D5 PR and keep the real owner identity for authenticated inspection; verify approved manifest from an independent owner channel and validate sandbox in an isolated test VM. This does not modify any AC, CON or architecture.
