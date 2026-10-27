# AIO MVP v0.13 — P01 D5 NINTH rework handoff

Previous reviewed SHA: `840727b2d4a33190fc11ee63f3ae5e1178667a4a`.
Normative base: `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`.
Scope: test-oracle candidate only, no implementation P01, no normative document changes.

## Findings and corrective changes

- `NINTH-D5-040`: All signed executable/script/import bytes are validated **before** any CPython identity probe. Additional probe runs under unprivileged test UID/GID; failures remain `NOT_CHECKED`. Negative test confirms that a malicious executable with wrong SHA cannot execute even one instruction during preflight.
- `NINTH-D5-041`: Reject symlink `argv[0]`. New `open_pinned_launch()` validates root-controlled component file, directory permissions, exact digest and inode; the actual SUT process is launched using inherited `/proc/self/fd/<n>` descriptors rather than a mutable path (both executable and pinned Python script). A positive synthetic ELF and Python smoke test proves the FD-backed launch works; changing the originally named path must not change the pinned inode. Production OS integrity is NOT_CHECKED.
- `NINTH-D5-042`: All 63 P01 acceptance cases now **unconditionally** request `execve_trace` from the trusted collector, independently authenticate its witness alongside per-AC proofs, then run `verify_execution_closure()` against the owner-signed component SHA map before treating any AC result as accepted. Requires complete kernel process trace, every descendant's execve and dynamically loaded component, zero gaps/drops and no unapproved executable or loaded artifact. Missing trace, lost events or unknown child returns `NOT_CHECKED`. This code does not claim the future OS collector is deployed.

## Test evidence boundaries

Initial targeted regressions: 5 FAIL against previous code (`840727b2...`), then 7 PASS after corrections. Final targeted Python FD smoke tests, 63 acceptance collection and isolated regression tests are separate from actual SUT AC PASS. Acceptance without approved SUT and owner policy intentionally yields `NOT_CHECKED`. Exact runner profile OQ-09/A (Ubuntu 24.04, Python 3.12 pinned) is NOT_CHECKED. External owner-approved trust root, signed collector, real kernel/audit tracer, OS/CI/Git test evidence and off-node backup remain NOT_CHECKED. P01 runtime 27 AC remain NOT_CHECKED; P02 BLOCKED.

## Reviewer challenges

1. Verify-before-execute: create a fake CPython executable that changes a synthetic marker but has wrong SHA; it must not be run by privileged admission.
2. Symlink/TOCTOU: alter `argv[0]` symlink after preflight; fail closed or show the actual launch is pinned to the validated descriptor. Test CPython script FD pinning too.
3. Global trace: case lacking `subprocess_audit` must still require authenticated `execve_trace`. A signed primary ELF that spawns unsigned `/bin/sh`, missing child event, loaded unsigned dependency, dropped kernel event or incomplete history must never PASS.
4. Verify `execve_trace` is genuinely produced from independently trusted kernel/audit monitor on the future runner; a JSON with `trace_complete=true` cannot by itself count as real OS evidence.
5. Run all unit/regression/integrity tests on exact SHA; record exit codes. All application runtime AC remain NOT_CHECKED until implementation and independent evidence.

No merge, deploy, production work or normative edits are authorized by this report.
