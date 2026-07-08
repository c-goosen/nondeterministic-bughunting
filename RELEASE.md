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
- `bughunt-audit-report`: Phase 2 of the HTML report now includes a **SAST
  Evidence section** — a tool-status grid (which scanners ran, raw-hit counts vs.
  promoted-finding counts) and per-tool collapsible finding tables, sourced
  deterministically from `VULN-FINDINGS.json`. A "SAST Evidence" nav anchor is
  added. The report generator reads `summary.raw_hits` and `summary.tools` from
  `VULN-FINDINGS.json`; raw tool output files (`.semgrep.json`, `.osv.json`, etc.)
  in the output directory are used as a fallback source for raw hit counts.
- `bughunt-vuln-scan`: `VULN-FINDINGS.json` summary extended with a `raw_hits`
  object recording pre-dedup tool output counts per scanner, and `govulncheck`
  added to `summary.tools`. Both fields feed the new HTML report SAST Evidence
  section. README updated to list govulncheck as the sixth pre-scan tool.
- **Token-efficiency pass** across all `bughunt-*` skills — reduces orchestrator
  context load and per-subagent prompt sizes without changing observable behaviour:
  - `bughunt-triage`: compact verifier prompt is now the **default** for all Phase 3b
    spawns (full prose reserved for the Phase 3d judge only — saves ~1 000 tokens ×
    findings × votes per run); §3a stripped to the exclusion-rules block only (~80
    lines removed, compact prompt already embeds the condensed list); phase 1–5
    checkpoints no longer repeat the `context` dict (already in `phase0.json`);
    Phase 4 ranking prompt omits null threat-model/security-context stanzas; `##
    Testing` and `## Design notes` extracted to `DESIGN.md`.
  - `bughunt-vuln-scan`: per-subagent review brief WHAT-TO-LOOK-FOR / DO-NOT-REPORT
    compressed from 37 lines to 3; disprove brief compressed from ~300 words to
    ~100; empty Security Context seed block now suppressed instead of sent as
    "none"; `## Provenance` extracted to `PROVENANCE.md`.
  - `bughunt-patch`: `TRIAGE.json` input fast-paths past the field-alias step (already
    canonical); `## Testing` and `## Design notes` extracted to `DESIGN.md`.
  - `bughunt-verify`: PoC-author PROCEDURE brief halved (~20 lines → 10), same four
    constraints preserved.
  - `_lib/async-recovery.md` (new): shared `async_launched` recovery procedure,
    referenced from triage and patch instead of duplicated inline.

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
