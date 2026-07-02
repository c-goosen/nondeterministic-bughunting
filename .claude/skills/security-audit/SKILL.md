---
name: security-audit
description: >-
  End-to-end security audit orchestrator. Drives the full pipeline —
  threat-model → vuln-scan → triage → patch — and folds the Cloudflare
  security-audit methodology (reconnaissance, hunting, attack classes,
  validation & reporting) into each stage. Use when asked to "run a full
  security audit", "do a security review and fix the findings", "pen-test
  this codebase end to end", or "find and patch vulnerabilities". Produces a
  threat model, validated findings, a human report, machine-readable
  findings.json, and candidate patches.
---

<!--
  security-audit (orchestrator) — combined work.
  This SKILL.md is net-new glue authored for nondeterministic-bughunting and is
  licensed under the MIT License (see /LICENSES/MIT-Cloudflare.txt for the MIT text;
  copyright for this file: 2026 Christo Goosen).

  It composes two upstream works, each retaining its own license:
    • Cloudflare security-audit methodology (MIT)  — the sibling .md/.json/.cjs files
      in this directory (RECONNAISSANCE, HUNTING, ATTACK-CLASSES,
      VALIDATION-AND-REPORTING, report-schema.json, validate-findings.cjs).
    • Anthropic defending-code pipeline (Apache-2.0) — the threat-model, vuln-scan,
      triage, and patch skills in ../.
  See /NOTICES.md for full attribution.
-->

# Security Audit (orchestrator)

You are running a **complete security audit** of a codebase, from attack-surface
mapping through candidate fixes. This skill is the conductor: it sequences four
specialist skills and applies a battle-tested manual-audit methodology at each
step.

This skill combines two upstream sources (see [/NOTICES.md](../../../NOTICES.md)):

- **Methodology** — Cloudflare's `security-audit` skill (MIT). The sibling files in
  this directory are vendored verbatim and define *how to hunt and validate*.
- **Pipeline** — Anthropic's defending-code skills (Apache-2.0): `threat-model`,
  `vuln-scan`, `triage`, `patch` (in `../`). These define *the staged artifacts
  and hand-offs*.

The core conviction from the Cloudflare methodology governs everything: **only
report exploitable vulnerabilities with real impact.** "An attacker could
theoretically…" is not a finding. "Send this request, get this result" is.

## Platform terminology

Agent-neutral terms used throughout the methodology docs:

- **Task tool** — the coding agent's delegation / sub-agent mechanism.
- **`research` agent** — a delegated agent optimized for focused codebase
  exploration and factual verification.
- **`general` agent** — a delegated agent that can investigate broadly and spawn
  focused research agents.
- **`subagent_type`** — the equivalent delegated-agent role on the current platform.

Preserve the specified roles, parallelism, prompts, and independence boundaries.

## Setup

Establish two paths before starting:

- **Target** — the codebase to audit (from the user's request, else the current
  working directory).
- **Output directory** — where every artifact goes. Ask the user, or default to
  `~/security-audit-skill/<repo-name>/run-<N>` where `<N>` is the next unused
  integer (check with `ls`). Separate runs → separate directories; coverage
  improves across runs.

If prior runs exist for this repo, read their `findings.json` / `TRIAGE.json`
first: skip known findings, target gaps, and resolve prior disagreements.

**Install the deterministic scanners once** (used by Phase 2 / `vuln-scan`):

```
bash ../vuln-scan/setup-tools.sh --check   # status
bash ../vuln-scan/setup-tools.sh           # install semgrep, osv-scanner, grype
```

## How the two sources align

| Phase | Methodology (Cloudflare, this dir) | Pipeline stage (Anthropic, `../`) | Primary artifact |
|---|---|---|---|
| 1. Recon | [RECONNAISSANCE.md](RECONNAISSANCE.md) | `threat-model` | `THREAT_MODEL.md`, `architecture.md` |
| 2. Hunt | [HUNTING.md](HUNTING.md), [ATTACK-CLASSES.md](ATTACK-CLASSES.md) | `vuln-scan` | `VULN-FINDINGS.json` |
| 3. Validate | [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) §Phase 3 | `triage` | `TRIAGE.json` |
| 4. Report | [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) §Phases 4–6 + [report-schema.json](report-schema.json) + [validate-findings.cjs](validate-findings.cjs) | — | `REPORT.md`, `findings.json` |
| 5. Patch | — | `patch` | `PATCHES/`, `PATCHES.md` |

## Workflow

Run the phases in order. Each phase invokes the named skill **and** applies the
linked methodology doc — the methodology sets the bar for what counts as a real
finding; the skill produces the structured artifact the next phase consumes.

### Phase 1 — Recon → threat model

1. Map architecture, trust boundaries, and input surfaces using
   [RECONNAISSANCE.md](RECONNAISSANCE.md). Determine the **baseline dynamically**:
   what is this app, and what comparable apps calibrate expected risk?
2. Invoke the **`threat-model`** skill (`../threat-model`). Use `bootstrap` when no
   owner is available, `interview` when one is, or `bootstrap-then-interview` when
   both code and owner are present. Write `THREAT_MODEL.md`.
3. Summarize recon + threat model into `architecture.md`; this feeds Phase 2 agent
   prompts. Note any prior-run findings here.

### Phase 2 — Hunt → vuln-scan

1. Select attack-class scopes from [ATTACK-CLASSES.md](ATTACK-CLASSES.md), weighted
   by the threat model and by gaps from prior runs.
2. Invoke the **`vuln-scan`** skill (`../vuln-scan`) against the target. It first
   runs a deterministic pre-scan (semgrep SAST, osv-scanner dependency CVEs, and
   grype image CVEs when a Dockerfile is present, plus a [Security
   Context](https://securitycontext.dev) history/CVE lookup when the target is a
   public GitHub repo), then reads `THREAT_MODEL.md` and spawns parallel review
   subagents per focus area — seeded with the scanner hits — writing
   `VULN-FINDINGS.json`.
3. Apply [HUNTING.md](HUNTING.md) orchestration and validation rules to steer the
   hunt: prioritize business logic, state-machine violations, and chained attacks
   over scanner-detectable classes. Push past lazy conclusions ("uses parameterized
   queries" → check every `sql.raw`, dynamic identifier, and bypass path).

### Phase 3 — Validate → triage

1. Invoke the **`triage`** skill (`../triage`) on `VULN-FINDINGS.json`. It verifies
   each finding is real, collapses duplicates, re-ranks by derived exploitability,
   and tags an owner, writing `TRIAGE.json`.
2. Enforce Phase 3 of [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md):
   independently try to **disprove** every surviving finding. Drop anything that
   needs the word "potentially". Demote defense-in-depth gaps to hardening notes.

### Phase 4 — Report → findings.json

1. Write `REPORT.md` and `FINDINGS-DETAIL.md` per Phases 4–6 of
   [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md).
2. Produce machine-readable `findings.json` conforming to
   [report-schema.json](report-schema.json), then validate it:
   `node validate-findings.cjs <output-dir>/findings.json`.
3. Independently verify every factual claim and reconcile all outputs (counts,
   severities, file:line references) before declaring the report final.

### Phase 5 — Patch → candidate fixes

1. Invoke the **`patch`** skill (`../patch`), preferring `TRIAGE.json` as input
   (falls back to `VULN-FINDINGS.json`).
2. Patches are written as **inert diffs for human review** under
   `PATCHES/bug_NN/` with `PATCHES.md` / `PATCHES.json`. Do not apply them
   automatically; present them for the maintainer to accept.

## Severity (shared rubric)

Severity = likelihood × impact. From the Cloudflare methodology:

- **CRITICAL** — unauthenticated RCE, full DB dump, admin takeover without creds.
- **HIGH** — authenticated RCE, SQLi with exfiltration, stored XSS for all users,
  auth bypass, or an explicit RBAC boundary completely defeated for a consequential
  action.
- **MEDIUM** — conditional XSS, CSRF with meaningful state change, secret
  disclosure, business-logic bypasses with real but limited blast radius.
- **LOW** — non-secret info disclosure, effortful DoS, hardening gaps.

Keep the pipeline skills' severities reconciled to this rubric when they disagree.

## Anti-patterns (do not do these)

1. Listing every OWASP deviation as a finding.
2. Rating defense-in-depth gaps HIGH/CRITICAL.
3. Ignoring the deployment model (CDN-layer rate limiting is valid architecture).
4. Treating designed, trusted behavior as a bug.
5. Padding the report with LOWs to look thorough.
6. "Potential"/"theoretical" findings without proof.
7. Ignoring what the codebase does well — say so; it builds trust.
8. Building exploits from unverified parser/runtime assumptions — cite or test.
9. Skipping business-logic and creative/chained attacks.
10. Giving up too easily.

## Artifacts produced

```
<output-dir>/
  architecture.md      # Phase 1 recon summary
  THREAT_MODEL.md      # Phase 1 (threat-model skill)
  VULN-FINDINGS.json   # Phase 2 (vuln-scan skill)
  TRIAGE.json          # Phase 3 (triage skill)
  REPORT.md            # Phase 4
  FINDINGS-DETAIL.md   # Phase 4
  findings.json        # Phase 4 (validated against report-schema.json)
  PATCHES/             # Phase 5 (patch skill) — inert diffs for review
```
