# Interview talking points: detection-rules-as-code

1. **Why detection-as-code.** It gives you review, history, rollback and tests. The regression demo is the pitch: a one-character "broaden the match" change got caught by a near-miss FP sample before it could flood the queue.
2. **How I pick FP samples.** They're near-misses, not random noise: `vssadmin list shadows` for the shadow-delete rule, `nc -zv` for the reverse-shell rule, `-Environment` for `-e`. Each one marks a boundary of the rule.
3. **Two engines.** My evaluator proves the *semantics* against samples. pySigma proves the rule *compiles* for a real SIEM backend. Both run in CI and the SPL is uploaded as an artifact.
4. **Linter checks.** UUID uniqueness (duplicates break SIEM sync), ATT&CK technique tags (for coverage maps), deprecated aggregation syntax, undefined selections in the condition, and missing tests. A rule without a test can't merge.
5. **Known evasions.** PowerShell parameter abbreviation (`-ec`), `/e`, renamed binaries (Image endswith fails, so use OriginalFileName), and caret obfuscation in cmd. Next steps: `|windash` and OriginalFileName.
6. **Next steps.** An ATT&CK Navigator layer generated from tags, a replay against public EVTX datasets for a real FP rate, and a `sigma check` from sigma-cli.
