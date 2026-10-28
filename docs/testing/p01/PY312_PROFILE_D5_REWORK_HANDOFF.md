# D5 Python 3.12 Profile Compatibility Rework — Developer Handoff

## Reviewed baseline and independent evidence

Previous exact GitHub HEAD: 11a35d29d1496943dabfdc5e180d00d620461f63
Normative Base: 9d54e4e546753e8f09b8e9d5f4e9d95142f976e8

The independent reviewer reported two profile runs on an isolated rootless VPS test container:

- Python 3.13.18, pytest 7.4.4, cryptography 46.0.4: 287 PASS, 0 FAIL, 0 SKIP; exit 0; Git tree clean.
- Python 3.12 (normative profile): 284 PASS, 2 FAIL, 1 SKIP.
- P01 runtime acceptance intentionally NOT RUN; OQ-09/A not independently provisioned/approved.
- GitHub owner review for exact SHA NOT_CHECKED; no GitHub Actions runs were found for the SHA.

These figures are reported for the **previous** HEAD, not as results of this new change.

## Root cause — three tests hardcode Python 3.13

1. tests/test_p01_ninth_review_regressions.py::test_041_pinned_python_exec_from_root_controlled_fd contained a hardcoded /usr/bin/python3.13 and an unsafe version-dependent SKIP when absent.
2. tests/test_p01_tenth_review_regressions.py::test_044_unreadable_pinned_script_rejected_as_not_checked used /usr/bin/python3.13 in the FD-pinned launch.
3. tests/test_p01_tenth_review_regressions.py::test_044_readable_script_passes_access_preflight similarly required /usr/bin/python3.13.

## Precise test-only remediation

All three tests now derive their OS-installed system interpreter from the *running* Python version:

    Path(f'/usr/bin/python{sys.version_info.major}.{sys.version_info.minor}')

They require the matching system executable to exist and resolve it with strict=True. On approved Ubuntu 24.04 / Python 3.12, this targets /usr/bin/python3.12; on Python 3.13, /usr/bin/python3.13.

Important security boundary: DO NOT use sys.executable as a fallback. In virtualenvs it may point to an untrusted user-writable directory. open_pinned_launch correctly rejects such components. The approved system binary remains SHA-256 pinned, FD-backed and subject to its root-controlled ownership/directory checks. The negative unreadable-script denial and positive readable-script access assertions remain unchanged.

No change was made to production code, tests/p01_probe.py, tests/p01_oqa_attestation.py, tests/test_p01_acceptance.py, normative documents, frozen P01_ORACLES.json or any OQ-09/A policy/authority.

## Tests and limitations

Local development environment has Python 3.13.5 and no installed Python 3.12. A synthetic pinned Python-launch smoke test against the older locally available D5 probe with a root-controlled /usr/bin/python3.13 executable passed; a naive sys.executable virtualenv path was correctly rejected. **Neither test is an exact-new-SHA full pytest pass.**

A full checkout and the two-profile full D5 suite have not been executed on the new commit. The independent reviewer must verify each of the three named test functions, the full regression suite, acceptance collection, compileall and skip reasons at the NEW HEAD in an approved isolated rootless test environment. Record Python 3.12 and 3.13 results separately and ensure security exclusions are not bypassed.

## External pending gates

OQ-09/A attester, actual kernel audit, independent signer OS isolation, read-only observer, real P01 runtime AC, authenticated owner approval AC-N-SEC-05.3, GitHub workflow runs and authorization for merge/deploy remain NOT_CHECKED or forbidden, as applicable.

D5 = REVIEW_PENDING / CHANGES_REQUIRED pending independent new-SHA review; P01 = NOT_COMPLETED; P02 = BLOCKED. No merge/deploy.