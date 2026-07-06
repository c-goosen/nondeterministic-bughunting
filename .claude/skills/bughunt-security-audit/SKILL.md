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
mapping through candidate fixes, test payloads, and a shareable HTML report. This skill
is the conductor: it sequences **seven** core specialist skills — plus an
optional **execution-verification** pass (`bughunt-verify`) that runs PoCs in
a sandbox — and applies a battle-tested manual-audit methodology at each step.

**An audit run is not complete until Phase 7 writes `<output-dir>/index.html`.**
Phases 1–6 produce the machine artifacts; Phase 7 renders the shareable HTML
report (dark-themed, self-contained — visual reference:
`~/security-audit-skill/openclaw/run-1/index.html`; generator:
`../bughunt-audit-report/generate-report.py`).

This skill combines two upstream sources (see [/NOTICES.md](../../../NOTICES.md)):

- **Methodology** — Cloudflare's `bughunt-security-audit` skill (MIT). The sibling files in
  this directory are vendored verbatim and define *how to hunt and validate*.
- **Pipeline** — Anthropic's defending-code skills (Apache-2.0): `bughunt-threat-model`,
  `bughunt-vuln-scan`, `bughunt-triage`, `bughunt-patch` (in `../`). These define *the staged artifacts
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
- **Output directory** — where every artifact goes. Resolve it in this order,
  and **never default to `~/security-audit-skill/*`**:
  1. If running inside the `nondeterministic-bughunting` repo (a `targets/`
     directory exists at the repo root), default to
     `targets/<repo-name>/run-<N>` — keep audit artifacts next to the audited
     target, in-repo.
  2. Otherwise, **ask the user** which directory to place output in, and
     prompt them to create a directory for it rather than assuming one.

  `<N>` is the next unused integer (check with `ls`). Separate runs → separate
  directories; coverage improves across runs.

If prior runs exist for this repo, read their `findings.json` / `TRIAGE.json`
first: skip known findings, target gaps, and resolve prior disagreements.

**Install the deterministic scanners once** (used by Phase 2 / `bughunt-vuln-scan`):

```
bash ../bughunt-vuln-scan/setup-tools.sh --check   # status
bash ../bughunt-vuln-scan/setup-tools.sh           # install semgrep, osv-scanner, grype
```

## How the two sources align

| Phase | Methodology (Cloudflare, this dir) | Pipeline stage (Anthropic, `../`) | Primary artifact |
|---|---|---|---|
| 1. Recon | [RECONNAISSANCE.md](RECONNAISSANCE.md) | `bughunt-threat-model` | `THREAT_MODEL.md`, `architecture.md` |
| 2. Hunt | [HUNTING.md](HUNTING.md), [ATTACK-CLASSES.md](ATTACK-CLASSES.md) | `bughunt-vuln-scan` | `VULN-FINDINGS.json` |
| 3. Validate | [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) §Phase 3 | `bughunt-triage` | `TRIAGE.json` |
| 3.7 Execute-verify (optional) | Cloudflare VDH Hunt/Validation (PoC-as-test, sandboxed) | `bughunt-verify` | `VERIFY.json`, `VERIFY/` |
| 4. Report | [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) §Phases 4–6 + [report-schema.json](report-schema.json) + [validate-findings.cjs](validate-findings.cjs) | — | `REPORT.md`, `findings.json` |
| 5. Patch | — | `bughunt-patch` | `PATCHES/`, `PATCHES.md` |
| 6. Payloads | [ATTACK-CLASSES.md](ATTACK-CLASSES.md) (repro inputs) | `bughunt-exploit-payloads` | `PAYLOADS.json`, `PAYLOADS.md` |
| 7. Report page | — | `bughunt-audit-report` | `index.html` |

## Workflow

Run the phases in order. Each phase invokes the named skill **and** applies the
linked methodology doc — the methodology sets the bar for what counts as a real
finding; the skill produces the structured artifact the next phase consumes.

### Phase 1 — Recon → threat model

1. Map architecture, trust boundaries, and input surfaces using
   [RECONNAISSANCE.md](RECONNAISSANCE.md). Determine the **baseline dynamically**:
   what is this app, and what comparable apps calibrate expected risk?
2. Invoke the **`bughunt-threat-model`** skill (`../bughunt-threat-model`). Use `bootstrap` when no
   owner is available, `interview` when one is, or `bootstrap-then-interview` when
   both code and owner are present. Write `THREAT_MODEL.md`.
3. Summarize recon + threat model into `architecture.md`; this feeds Phase 2 agent
   prompts. Note any prior-run findings here.

### Phase 2 — Hunt → vuln-scan

1. Select attack-class scopes from [ATTACK-CLASSES.md](ATTACK-CLASSES.md), weighted
   by the threat model and by gaps from prior runs.
2. Invoke the **`bughunt-vuln-scan`** skill (`../bughunt-vuln-scan`) against the target. It first
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
4. **Gapfill (coverage).** `bughunt-vuln-scan`'s Step 2b runs a bounded second
   hunt over files no focus area covered and no first-round finding cited —
   Cloudflare's Gapfill stage. Confirm the scan reports its coverage gap and
   that files carrying an unconsumed semgrep / Security Context seed were
   re-hunted (or explicitly ranked out). If you drove the scan with
   `--no-gapfill` for speed, note the unread files as a known coverage gap in
   `architecture.md`.

### Phase 3 — Validate → triage

1. Invoke the **`bughunt-triage`** skill (`../bughunt-triage`) on `VULN-FINDINGS.json`. It verifies
   each finding via a **multi-model verifier panel** (one model per vote) and a
   **judge on the largest capable model available** for split votes, then
   collapses duplicates, re-ranks by derived exploitability, and tags an owner,
   writing `TRIAGE.json`.
2. Enforce Phase 3 of [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md):
   independently try to **disprove** every surviving finding. Drop anything that
   needs the word "potentially". Demote defense-in-depth gaps to hardening notes.

### Phase 3.5 — Feedback (prompt rewrite for the next round/run)

Cloudflare's Feedback stage: turn what validation *rejected* into sharper
prompts, so coverage and precision improve instead of the same false
positives recurring. This is cheap — it reads `TRIAGE.json`, which already
carries `refute_reasons`, `exclusion_rule`, and `first_links` per finding —
and it is the mechanism by which "coverage improves across runs" actually
happens rather than being left to chance.

1. **Mine the rejects.** From `TRIAGE.json`, tally the `refute_reasons` and
   `exclusion_rule` values across `false_positive` findings. A recurring
   reason (e.g. many rule-8 operator-input rejects, or repeated
   `intentional_behavior`) is a class the hunt keeps over-reporting.
2. **Mine the gaps.** Note subsystems that produced only false positives, or
   that no finding touched at all, cross-referenced with `architecture.md`'s
   coverage gap and any unconsumed Step 0 seeds.
3. **Write `feedback.md`** in the output dir with two short lists:
   - **FP-avoidance rules** — one line each, in the shape `--fp-rules`
     accepts (e.g. "operator-set env vars are trusted here — rule 8").
   - **Missed-area leads** — files/subsystems to scope explicitly next time.
4. **Close the loop.** Feed `feedback.md` forward: pass it as
   `bughunt-vuln-scan --extra feedback.md` (and `bughunt-triage --fp-rules
   feedback.md`) on the next run of this repo, and cite it in the next
   `THREAT_MODEL.md`. Within a single audit, if the reject rate is high and
   time allows, you may re-run Phase 2 on the missed-area leads immediately
   rather than deferring to a future run.

`feedback.md` is advisory input to future prompts, never a finding source —
it tunes the hunt, it does not add or remove verdicts on its own.

### Phase 3.7 — Execute-verify → PoCs (optional; authorized targets only)

The rest of the pipeline is static: triage *believes* a finding is real, but
nothing has been *run*. This optional phase closes that gap the way the
Cloudflare harness does — every finding earns `execution_verified` only when a
proof-of-concept, written as a test **against the untouched codebase**,
produces an observable signal in a sandbox.

1. **Gate on authorization.** Only run this against a target you're authorized
   to execute — a local checkout, a lab/CTF instance, or an active engagement.
   Skip the phase (note why) for any target you cannot run safely; Phases 4–7
   still work on the static findings.
2. Invoke the **`bughunt-verify`** skill (`../bughunt-verify`) on `TRIAGE.json`.
   It selects `true_positive` findings that are `exploitable` or
   `needs_manual_test`, writes a PoC-as-test per finding, and runs each in
   `run-sandboxed.sh` (network-denied, target read-only, timed). Verdicts:
   `execution_verified`, `not_reproduced`, or `inconclusive` — decided by the
   observed signal, never the exit code alone.
3. Carry `VERIFY.json` into Phase 4: when writing `REPORT.md` and
   `findings.json` by hand, mark each execution-verified finding distinctly
   (fold the observed signal into the finding's `execution.expected_result`)
   and surface `not_reproduced` as its own state. `not_reproduced` does
   **not** overturn triage's verdict — a PoC that didn't fire may just be a
   wrong PoC. (The HTML generator in Phase 7 renders from
   `TRIAGE.json`/`findings.json`; it does not read `VERIFY.json` directly, so
   the verified status must be reflected in those hand-written artifacts.)

### Phase 4 — Report → findings.json

1. Write `REPORT.md` and `FINDINGS-DETAIL.md` per Phases 4–6 of
   [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md).
2. Produce machine-readable `findings.json` conforming to
   [report-schema.json](report-schema.json), then validate it:
   `node validate-findings.cjs <output-dir>/findings.json`.
3. Independently verify every factual claim and reconcile all outputs (counts,
   severities, file:line references) before declaring the report final.

### Phase 5 — Patch → candidate fixes

1. Invoke the **`bughunt-patch`** skill (`../bughunt-patch`), preferring `TRIAGE.json` as input
   (falls back to `VULN-FINDINGS.json`).
2. Patches are written as **inert diffs for human review** under
   `PATCHES/bug_NN/` with `PATCHES.md` / `PATCHES.json`. Do not apply them
   automatically; present them for the maintainer to accept.
3. **Confirm the fix (if Phase 3.7 ran).** Re-invoke `bughunt-verify
   TRIAGE.json --with-patch PATCHES/` to re-run each verified PoC against a
   patched copy of the target: `patch_confirmed` is true only when the
   success signal disappears and the build still works. This is the
   PoC-fails-on-`main`, PoC-passes-after-fix double check.

### Phase 6 — Payloads → repro inputs

1. Invoke the **`bughunt-exploit-payloads`** skill (`../bughunt-exploit-payloads`) on the run
   directory. It reads `findings.json` (preferred — uses each confirmed entry's
   `execution.payloads`) or `TRIAGE.json`, and writes `PAYLOADS.json` /
   `PAYLOADS.md`: one card per `exploitable` / `needs_manual_test` true positive,
   each carrying the literal input, how to fire it at a controlled instance, and
   the observable success signal.
2. **Authorized testing only.** Payloads are inert text tied to findings already
   verified in this run — never executed here, never aimed at third parties. Any
   SSRF/exfil payload must point at a canary the tester owns (enforced in the
   skill's guardrails). `mitigated`/rejected findings are skipped with a reason.

### Phase 7 — Report page → index.html (required final step)

**Do not declare the audit finished until this phase completes.**

1. Read `../bughunt-audit-report/SKILL.md` and follow it on `<output-dir>`.
2. Write `<output-dir>/narrative.json` — prose slots summarized faithfully from
   `architecture.md`, `REPORT.md`, and `THREAT_MODEL.md` (see audit-report skill
   for the schema). Do not invent facts. Include run provenance:
   **`run_model`** (the model you ran this audit on — e.g. `claude-opus-4-8`,
   or the Cursor slug like `glm-5.2` for a second-pass run) and **`run_tokens`**
   (the run's total token usage) so the report header records which model
   produced it and at what cost. Record the real model; leave `run_tokens` out
   rather than guessing a number.
3. Generate the HTML report (matches the run-1 template layout/styling):
   ```
   python3 .claude/skills/bughunt-audit-report/generate-report.py <output-dir>
   ```
   This writes `<output-dir>/index.html`. Counts, severity badges, findings
   tables, and patch cards are derived from `TRIAGE.json` / `PATCHES.json` /
   `PAYLOADS.json` / `findings.json` — never hand-edit `index.html` to fix numbers.
4. Verify the file exists (`ls <output-dir>/index.html`). Present the report to
   the user as `file://<absolute-output-dir>/index.html`. Do not open a browser
   or push it anywhere.

If `PAYLOADS.json` is missing (Phase 6 skipped), the report still generates;
payload and patch sections show empty-state cards.

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
  VULN-FINDINGS.json   # Phase 2 (vuln-scan skill; incl. Step 2b gapfill round)
  TRIAGE.json          # Phase 3 (triage skill)
  feedback.md          # Phase 3.5 — FP-avoidance rules + missed-area leads for next run
  VERIFY.json          # Phase 3.7 (bughunt-verify, optional) — execution-verified results
  VERIFY/              # Phase 3.7 — per-finding PoCs + run logs (authorized targets only)
  REPORT.md            # Phase 4
  FINDINGS-DETAIL.md   # Phase 4
  findings.json        # Phase 4 (validated against report-schema.json)
  PATCHES/             # Phase 5 (patch skill) — inert diffs for review
  PAYLOADS.json        # Phase 6 (exploit-payloads skill) — repro inputs
  PAYLOADS.md          # Phase 6 — human-readable payload cards
  index.html           # Phase 7 (audit-report) — REQUIRED; self-contained HTML report
```

## Audit completion checklist

Before telling the user the audit is done, confirm:

- [ ] `TRIAGE.json` and `findings.json` (validated) exist
- [ ] `REPORT.md` and `FINDINGS-DETAIL.md` exist
- [ ] `narrative.json` exists (prose slots for the HTML report)
- [ ] **`index.html` exists** — generated by `generate-report.py`, not hand-written
- [ ] You gave the user a `file://…/index.html` link to the run directory
