# AIO MVP v0.13 — Eighth D5 Rework Handoff (SEVENTH-REVIEW-039)

## Scope / exact baseline

- Previous Independent Reviewer D5 verdict: `CHANGES_REQUIRED` on head `e3e0264ab21b868a8136bb559b091f1e4a1dc977`.
- Normative base: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8` (unchanged).
- Scope: **D5 test-oracle candidate only**, before any P01 implementation. No normative changes, no deployment, no owner approval, no P01 runtime PASS.

## Reproduction-first and correction

`SEVENTH-REVIEW-039` reproduced by eight negative/positive pytest parameter cases against old code: signed `/usr/bin/dash` + unsigned `payload.sh`, signed `/usr/bin/perl` + unsigned `payload.pl`, byte-identical renamed `/usr/bin/env` + unsigned payload, plus missing signed command-mode validation. Initial targeted run failed **6/6 cases** (one test is parametrized).

**Correction:** replaced blacklist-based launcher classification with explicit *owner-signed* field `sut_launch_mode`, with only these modes:

1. `direct_elf`: one absolute SHA-256-pinned ELF executable, **no additional launch argv elements** in the approved command. The test harness appends its disposable fixture filename only after validating the approved command. Neither `dash script.sh` nor renamed `env python3 script.py` is a valid direct mode.
2. `pinned_python_script`: an SHA-256-pinned executable that demonstrates a CPython identity in bounded `-I -S -c` probe, plus **exactly one absolute, pinned Python script**. No wrapper flags or positional extras are allowed in the approved launch argv; the fixture pathname is appended later by the harness.
3. No mode, unsupported mode, command shape ambiguity, missing script, modified bytes, dirty checkout or signature mismatch: `NOT_CHECKED` (fail closed).

This is a **D5 harness policy**, not a change to approved SPEC or P01 runtime API. The owner-signed policy schema retains its candidate name but requires the new field; there is no approved deployed policy being silently migrated.

Added `tests/test_p01_eighth_review_regressions.py`, retained all prior regressions, and updated older tests to explicitly supply the new mode. The acceptance fixture now obtains its mode exclusively from the externally signed policy. No SUT self-report can select the mode.

## Independent re-review checklist

- Verify a renamed wrapper, `/usr/bin/dash`, `/usr/bin/perl`, `env python3`, and missing/forged launch modes all fail closed even with valid SHA of the launcher.
- Verify a correctly signed direct ELF and pinned absolute Python script have a positive unit-test path.
- Verify owner signature pins launch mode, command array digest, component bytes, exact HEAD, and external trust anchor; no launch authority derives from basename alone.
- Probe interpreter identity spoofing, shebang/child exec behavior, extension modules, runtime import closure and command/file mutation between validation and launch. **The pre-execution validator is not independent proof of actual descendant exec/import provenance.** Trusted runtime evidence remains required before P01 acceptance PASS.
- Verify `AC-N-15.2` protected synthetic evidence ownership remains correct, with runner witness protected separately, and no regression for other 27 AC.

## Results and outstanding conditions

Developer local regression/integrity test counts and pytest commands are recorded separately in handoff response. They must be independently reproduced on the **new exact Git SHA**. No approved OQ-09/A Ubuntu 24.04 / Python 3.12 runner, real owner Ed25519 trust-root, complete trusted collectors, security CI, Git scan, off-node backup or `AC-N-SEC-05.3` inspection has been demonstrated. All 27 runtime AC remain `NOT_CHECKED`; P01 is not completed and P02 remains blocked. Never interpret a Python unit-test PASS as a runtime acceptance PASS.
