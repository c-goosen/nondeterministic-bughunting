# bughunt-triage — Design notes and smoke tests

## Testing this skill

Smoke test (five-finding fixture: 2 real, 1 dup, 2 FP):

```
/bughunt-triage .claude/skills/bughunt-triage/fixtures/canary-findings.json --auto --repo targets/canary
```

Expected: f001 and f003 confirmed; f002 duplicate of f001; f004 dropped
(`misread_code`: it's a read buffer, not a randomness source); f005 dropped
(`already_handled`: there is a null check at line 68).

Or against pipeline output:

```
vuln-pipeline run drlibs --runs 3 --parallel --stream
/bughunt-triage results/drlibs/<ts>/ --repo targets/drlibs
```

Hand-check a sample of TRUE_POSITIVE/HIGH results (the `first_links` should
point at real call sites) and a sample of FALSE_POSITIVE rejects (the
`exclusion_rule` or `refute_reasons` should be defensible).

---

## Design notes

- **Checkpoints are per-phase JSON**, not conversation state. The pipeline's
  `--resume <session_id>` (docs/pipeline.md) restores transcript history but
  doesn't help when the orchestrator's context window itself fills;
  file-backed checkpoints let a brand-new session pick up from the last
  completed phase. `./.triage-state/` is scratch — add to `.gitignore`.
- **Multi-model verify + judge:** each vote runs on a different model from
  `verifier_models` (Phase 0e) to reduce single-model blind spots; split /
  tie / majority-CANNOT_VERIFY outcomes go to `judge_model` — the largest /
  most capable model available (`claude-opus-4-8-thinking-high` preferred).
  Unanimous or clear-majority findings skip the judge to save cost.
- **Dedupe runs before verify** to cut verifier spend by the duplication
  factor (often 2-4x on multi-scanner input) at the cost of one cheap
  subagent.
- **Semantic dedupe is one agent**, given only id/file/line/category/title:
  enough to cluster, not enough to leak one scanner's reasoning into
  another finding's verification.
- **Bash is allowed narrowly** for `git log` (owner hints), `jq`/`find`
  (ingest), and `python3 .claude/skills/_lib/checkpoint.py` (state I/O).
  The actual safety property is "no execution of target code," which is
  preserved.
- **`CANNOT_VERIFY`** exists so verifiers aren't forced into a false
  binary. It maps to `needs_manual_test` under recall policy and to a drop
  under precision policy.
- **Threat-model boost is capped at one step** so a stated threat can't
  re-inflate a LOW back to HIGH and defeat the precondition rule.
- **`severity_label` is separate from `severity`.** Sorting always uses the
  precondition-derived HIGH/MEDIUM/LOW; the label is presentation-layer for
  whatever standard the reviewer's tooling expects.
- **Pipeline `report.json` ingest is best-effort.** Those reports describe
  ASAN crashes with prose exploitability analysis rather than the
  file/line/category shape static verifiers expect. Expect more
  `needs_manual_test` verdicts on that input than on static-scanner JSON.
- **Sharding at ~40 parallel Tasks** is a conservative ceiling for typical
  agent-spawn limits; tune up if your runtime allows.
- **No network**, deliberately, with the one narrow exception in Phase 0d
  (a cached Security Context read, gated to public GitHub repos, never
  feeding Phase 3 verification). General CVE-database enrichment and
  upstream-fix checks would help ranking further but would break the
  air-gapped-review property, so they stay out.
