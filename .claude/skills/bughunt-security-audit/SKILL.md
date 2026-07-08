---
name: bughunt-security-audit
description: >-
  End-to-end security audit orchestrator. Drives the full pipeline —
  threat-model → vuln-scan → triage → patch → payloads → report — and folds
  the Cloudflare security-audit methodology (reconnaissance, hunting, attack
  classes, validation & reporting) into each stage. Use when asked to "run a
  full security audit", "do a security review and fix the findings", "pen-test
  this codebase end to end", or "find and patch vulnerabilities". Produces a
  threat model, validated findings, a human report, machine-readable
  findings.json, candidate patches, authorized test payloads, and a
  self-contained HTML report (index.html).
---

<!--
  security-audit (orchestrator) — MIT License (copyright 2026 Christo Goosen).
  Composes: Cloudflare security-audit methodology (MIT) — sibling .md/.json/.cjs
  files in this directory; Anthropic defending-code pipeline (Apache-2.0) — the
  bughunt-* skills in ../. See /NOTICES.md for full attribution.
-->

# Security Audit (orchestrator)

You are running a **complete security audit** from attack-surface mapping
through candidate fixes, test payloads, and a shareable HTML report. This skill
sequences seven specialist skills and applies the Cloudflare audit methodology
at each step. **The run is not complete until Phase 7 writes `<output-dir>/index.html`.**

This skill combines two upstream sources (see [/NOTICES.md](../../../NOTICES.md)):
- **Methodology** — Cloudflare's bughunt methodology (MIT). The sibling files in
  this directory define *how to hunt and validate*.
- **Pipeline** — Anthropic's defending-code skills (Apache-2.0) in `../`. These
  define *the staged artifacts and hand-offs*.

The core conviction: **only report exploitable vulnerabilities with real impact.**
"An attacker could theoretically…" is not a finding. "Send this request, get
this result" is.

## Setup

Establish two paths before starting:

- **Target** — the codebase to audit (from the user's request, else cwd).
- **Output directory** — resolve in this order, **never default to `~/security-audit-skill/*`**:
  1. If a `targets/` directory exists at the repo root, use
     `targets/<repo-name>/run-<N>` (check `ls` for next unused `<N>`).
  2. Otherwise, **ask the user** which directory to use.

If prior runs exist, read their `findings.json` / `TRIAGE.json` first: skip
known findings, target gaps, and resolve prior disagreements.

Install the deterministic scanners once (used by Phase 2):
```
bash ../bughunt-vuln-scan/setup-tools.sh --check   # status
bash ../bughunt-vuln-scan/setup-tools.sh           # semgrep, osv-scanner, grype, gitleaks, checkov, govulncheck
```

## Phase-to-skill mapping

| Phase | Methodology (this dir) | Pipeline skill (`../`) | Primary artifact |
|---|---|---|---|
| 1. Recon | [RECONNAISSANCE.md](RECONNAISSANCE.md) | `bughunt-threat-model` | `THREAT_MODEL.md`, `architecture.md` |
| 2. Hunt | [HUNTING.md](HUNTING.md), [ATTACK-CLASSES.md](ATTACK-CLASSES.md) | `bughunt-vuln-scan` | `VULN-FINDINGS.json` |
| 3. Validate | [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) §Phase 3 | `bughunt-triage` | `TRIAGE.json` |
| 3.7 Execute-verify (optional) | Cloudflare VDH Hunt/Validation | `bughunt-verify` | `VERIFY.json`, `VERIFY/` |
| 4. Report | [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) §Phases 4–6 | — | `REPORT.md`, `findings.json` |
| 5. Patch | — | `bughunt-patch` | `PATCHES/`, `PATCHES.md` |
| 6. Payloads | [ATTACK-CLASSES.md](ATTACK-CLASSES.md) (repro inputs) | `bughunt-exploit-payloads` | `PAYLOADS.json`, `PAYLOADS.md` |
| 7. Report page | — | `bughunt-audit-report` | `index.html` |

## Workflow

### Phase 1 — Recon → threat model

1. Follow [RECONNAISSANCE.md](RECONNAISSANCE.md): launch the three parallel research
   agents to map architecture, trust boundaries, and input surfaces. Synthesize
   into `<output-dir>/architecture.md`. If Phase 1 reveals unexpected complexity
   (plugin system, multi-tenant arch, complex auth chains), launch additional
   agents before proceeding.
2. Invoke `/bughunt-threat-model` on the target. Use `bootstrap` when no owner
   is available, `interview` when one is present, or `bootstrap-then-interview`
   when both are available. Writes `THREAT_MODEL.md`.

### Phase 2 — Hunt → vuln-scan

1. Select attack-class scopes from [ATTACK-CLASSES.md](ATTACK-CLASSES.md), weighted
   by the threat model and by gaps from prior runs.
2. Invoke `/bughunt-vuln-scan <target>`. Apply [HUNTING.md](HUNTING.md) orchestration
   and validation rules to steer the hunt: prioritize business logic,
   state-machine violations, and chained attacks over scanner-detectable classes.
3. Confirm the scan reports its gapfill coverage. If run with `--no-gapfill`,
   note unread files as a known coverage gap in `architecture.md`.

### Phase 3 — Validate → triage

1. Invoke `/bughunt-triage VULN-FINDINGS.json --auto`. Pass `--fp-rules
   feedback.md` if it exists from a prior run.
2. Enforce [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) §Phase 3:
   independently try to **disprove** every surviving finding. Drop anything that
   needs the word "potentially". Demote defense-in-depth gaps to hardening notes.

### Phase 3.5 — Feedback (prompt rewrite for next run)

Mine the triage rejects to sharpen future prompts. This is cheap — `TRIAGE.json`
already carries `refute_reasons`, `exclusion_rule`, and `first_links` per finding.

1. **Mine the rejects.** Tally `refute_reasons` and `exclusion_rule` across
   `false_positive` findings. A recurring reason is a class the hunt keeps
   over-reporting.
2. **Mine the gaps.** Note subsystems that produced only false positives, or
   that no finding touched at all, cross-referenced with `architecture.md`.
3. **Write `feedback.md`** with two short lists:
   - **FP-avoidance rules** — one line each (e.g. "operator-set env vars are trusted here — rule 8").
   - **Missed-area leads** — files/subsystems to scope explicitly next time.
4. **Close the loop.** Pass `feedback.md` as `bughunt-vuln-scan --extra
   feedback.md` and `bughunt-triage --fp-rules feedback.md` on the next run.
   Within a single audit, if reject rate is high and time allows, re-run
   Phase 2 on missed-area leads immediately.

`feedback.md` tunes the hunt — it does not add or remove verdicts on its own.

### Phase 3.7 — Execute-verify → PoCs (optional; authorized targets only)

1. **Gate on authorization.** Only run against a target you're authorized to
   execute — a local checkout, a lab/CTF instance, or an active engagement.
   If you cannot run the target safely, skip this phase (note why) and proceed
   to Phase 4 on the static findings.
2. Invoke `/bughunt-verify TRIAGE.json` on the target. Writes `VERIFY.json`
   and per-finding PoCs under `VERIFY/`.
3. Carry `VERIFY.json` into Phase 4: mark execution-verified findings distinctly
   in `findings.json` (fold the observed signal into `execution.expected_result`).
   `not_reproduced` does **not** overturn triage's verdict — a wrong PoC ≠ no bug.

### Phase 4 — Report → findings.json

1. Write `REPORT.md` and `FINDINGS-DETAIL.md` per
   [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) §Phases 4–6.
2. Produce `findings.json` conforming to [report-schema.json](report-schema.json).
   Validate: `node validate-findings.cjs <output-dir>/findings.json`.
3. Independently verify every factual claim and reconcile all outputs (counts,
   severities, file:line references) before declaring the report final.

### Phase 5 — Patch → candidate fixes

1. Invoke `/bughunt-patch TRIAGE.json`. Patches land under `PATCHES/bug_NN/` as
   inert diffs for human review — do not apply them automatically.
2. **If Phase 3.7 ran:** re-invoke `/bughunt-verify TRIAGE.json --with-patch
   PATCHES/` to confirm each patch closes the verified PoC.

### Phase 6 — Payloads → repro inputs

Invoke `/bughunt-exploit-payloads <output-dir>`. Authorized testing only —
payloads are inert text for a human to fire at a controlled instance. Any
SSRF/exfil payload must point at a canary the tester owns.

### Phase 7 — Report page → index.html (required final step)

**Do not declare the audit finished until this phase completes.**

Invoke `/bughunt-audit-report <output-dir>` — it handles `narrative.json` and
runs `generate-report.py` to produce `<output-dir>/index.html`. Present the
result as `file://<absolute-output-dir>/index.html`. Do not open a browser or
push anywhere.

## Severity (shared rubric)

Severity = likelihood × impact. Keep pipeline skills' severities reconciled here:

- **CRITICAL** — unauthenticated RCE, full DB dump, admin takeover without creds.
- **HIGH** — authenticated RCE, SQLi with exfiltration, stored XSS for all users,
  auth bypass, or an explicit RBAC boundary completely defeated for a consequential action.
- **MEDIUM** — conditional XSS, CSRF with meaningful state change, secret
  disclosure, business-logic bypasses with real but limited blast radius.
- **LOW** — non-secret info disclosure, effortful DoS, hardening gaps.

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
  feedback.md          # Phase 3.5 — FP-avoidance rules + missed-area leads
  VERIFY.json          # Phase 3.7 (bughunt-verify, optional)
  VERIFY/              # Phase 3.7 — per-finding PoCs + run logs
  REPORT.md            # Phase 4
  FINDINGS-DETAIL.md   # Phase 4
  findings.json        # Phase 4 (validated against report-schema.json)
  PATCHES/             # Phase 5 (patch skill) — inert diffs for review
  PAYLOADS.json        # Phase 6 (exploit-payloads skill)
  PAYLOADS.md          # Phase 6 — human-readable payload cards
  index.html           # Phase 7 (audit-report) — REQUIRED; self-contained HTML
```

## Audit completion checklist

- [ ] `TRIAGE.json` and `findings.json` (schema-validated) exist
- [ ] `REPORT.md` and `FINDINGS-DETAIL.md` exist
- [ ] **`index.html` exists** — generated by `generate-report.py`, not hand-written
- [ ] You gave the user a `file://…/index.html` link
