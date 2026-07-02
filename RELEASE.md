# Release notes

## Unreleased

- README: corrected the pre-scan scanner count (five, not three), documented
  the shipped harness config (`.claude/settings.json`), and added a
  cross-model workflow — re-running the pipeline via the Cursor CLI agent
  with GLM 5.2 or Kimi K2.7 to prevent single-model blind spots, with the
  merged findings deduped in one `/bughunt-triage` pass.
- Added this `RELEASE.md`.
- Credited Devansh's _Needle in the Haystack_ as methodology prior art
  (`NOTICES.md` §5, README "Further reading").
- `bughunt-vuln-scan`: restructured the per-subagent review brief into four passes —
  seeds, **invariant decomposition** (enumerate the assumptions a slice
  depends on, then test each), hunt, and a **"what else?" second pass** — and
  added a **context-budget directive** so scaffolding doesn't crowd out code.
  Adopts the safe subset of the _Needle in the Haystack_ techniques; the
  aggressive "false anchoring" variant was deliberately softened to fit the
  skill's blue-team framing.

## v0.1.0 — 2026-07-02

Initial release of the agentic security-audit toolkit.

### Added

- **`bughunt-security-audit` orchestrator skill** — net-new MIT-licensed glue that
  drives the full pipeline (`bughunt-threat-model` → `bughunt-vuln-scan` → `bughunt-triage` →
  `bughunt-patch`) and folds the Cloudflare audit methodology (reconnaissance,
  hunting, attack classes, validation & reporting) into each stage. Ships
  with `report-schema.json` and a `validate-findings.cjs` checker for the
  machine-readable output.
- **`bughunt-threat-model` skill** — three modes (interview, bootstrap,
  bootstrap-then-interview) that all write `THREAT_MODEL.md` in a shared
  schema.
- **`bughunt-vuln-scan` skill** — deterministic pre-scan with five external
  scanners (semgrep, osv-scanner, grype, gitleaks, checkov) followed by a
  parallel LLM review fan-out seeded with the scanner hits; writes
  `VULN-FINDINGS.json`/`.md`.
- **`bughunt-triage` skill** — verifies raw findings, collapses duplicates, re-ranks
  by exploitability, and writes `TRIAGE.json`/`.md`; includes canary
  fixtures for self-testing.
- **`bughunt-patch` skill** — generates inert candidate diffs per verified finding
  with an independent reviewer pass; writes `PATCHES/` plus `PATCHES.md`
  and `PATCHES.json`.
- **`setup-tools.sh`** — one-shot installer for the five external scanners.
- **Security Context integration** — `bughunt-vuln-scan` and `bughunt-triage` pull cached
  fix-commit/CVE history from [securitycontext.dev](https://securitycontext.dev)
  for public GitHub targets, as advisory context only (best-effort,
  network-optional).
- **Cross-CLI support** — `.opencode/skills` and `.cursor/skills` symlink to
  `.claude/skills`, so OpenCode and Cursor share the same skill set.
- **Harness config** — `.claude/settings.json` pins the model and
  pre-approves the scanner and read-only shell commands the pipeline uses.
- **`targets/`** — gitignored scratch directory for codebases under audit.
- **Licensing** — combined work from
  [anthropics/defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)
  (Apache-2.0, pipeline skills) and
  [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
  (MIT, audit methodology); full attribution in `NOTICES.md` and
  `LICENSES/`.
