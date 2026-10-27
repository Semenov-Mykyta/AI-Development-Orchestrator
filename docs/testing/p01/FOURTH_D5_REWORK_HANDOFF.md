# Fourth D5 rework handoff — independent review required

Target P01 D5 oracle candidate only. Previous reviewed SHA: `10393856b6e5649bcd586aa2bb9c5edea65bc6e0`. Normative base `9d54e4e546753e8f09b8e9d5f4e9d95142f976e8`.

- FOURTH-D5-023: real/effective/saved/filesystem UID/GID, supplementary groups, CapEff/CapPrm/CapAmb and NoNewPrivs required; different effective UID must be rejected.
- FOURTH-D5-024: root-owned collector and ancestors must be non-SUT-writable, imported bytes match approved digest and are copied to root-controlled temporary path before import.
- FOURTH-D5-025: owner-signed policy binds `sut_executable_sha256` and runner checks dirty/untracked checkout and executable bytes independently of `git rev-parse HEAD` or argv.
- FOURTH-D5-026: dynamic reachable-history commit set for each ref compared with all commits actually scanned, not just tip SHA.
- FOURTH-D5-027: synthetic sentinel and protected evidence use deterministic `repeat_utf8_seed_v1` byte generators with independently computed SHA-256. Real bytes/backup still require independent collector proof.

Local subset: 46 PASS across oracle-integrity and the three previous regression modules plus fourth-review regressions, 63 acceptance tests collected, no genuine SUT => NOT_CHECKED, compileall PASS.

Not yet verified: full suite on approved OQ-09/A runner, installed root-controlled collector and signed owner root, independent Git-history scanner, real backup/sentinel bytes, OS/CI tests, bootstrap owner inspection. Signed digest alone does not prove byte provenance. Review potential import-time race, script/interpreter digests and OS identity limitations. No P01 runtime AC PASS. No normative document changes. P01 NOT_COMPLETED; P02 BLOCKED.
