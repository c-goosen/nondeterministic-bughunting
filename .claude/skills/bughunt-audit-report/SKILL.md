---
name: bughunt-audit-report
description: >-
  Render a self-contained HTML report (index.html) for a completed security
  audit run. Reads the run's machine-readable artifacts — TRIAGE.json,
  PATCHES.json, PAYLOADS.json, findings.json — plus a small narrative.json of
  prose slots, and emits a single-file dark-themed report showing every phase
  (recon → hunt → validate → report → patch → payloads), the ranked findings
  table, patch cards, and payload cards. Use as the final step of a
  security-audit run, or when asked to "generate the HTML report", "make an
  index.html for the audit", or "visualize the findings".
argument-hint: "<output-dir>"
allowed-tools:
  - Read
  - Write
  - Bash(python3 .claude/skills/bughunt-audit-report/generate-report.py:*)
  - Bash(ls:*)
  - Bash(jq:*)
---

# bughunt-audit-report

Final presentation step of a security audit. Turns the run's structured
artifacts into one shareable `index.html` — no server, no build, opens with
`file://`.

The report is **deterministic for everything that is a fact** (counts,
severities, findings rows, patch/payload cards): those come straight from the
JSON artifacts via `generate-report.py`, so the page can never disagree with
`TRIAGE.json`. The only thing you write by hand is prose that isn't in any
artifact — the recon narrative and executive summary — and that goes in a
`narrative.json` the script reads.

Invoke with `/bughunt-audit-report <output-dir>` where `<output-dir>` is the run
directory (e.g. `targets/<repo>/run-<N>` in-repo; never
`~/security-audit-skill/*`).

**Visual template:** the canonical layout/CSS is exemplified by
`~/security-audit-skill/openclaw/run-1/index.html`. This skill's
`generate-report.py` reproduces that dark-themed, phase-navigated report from
the run's JSON artifacts — do not hand-edit generated HTML.

## Inputs (all in `<output-dir>`)

| File | Role | Required |
|---|---|---|
| `TRIAGE.json` | metadata, ranked findings, summary counts | yes (or `findings.json`) |
| `findings.json` | schema-validated confirmed/rejected list → validation badge | recommended |
| `PATCHES.json` | Phase 5 patch cards | optional |
| `PAYLOADS.json` | Phase 6 payload cards | optional |
| `narrative.json` | prose slots (below) | optional but strongly recommended |

## Workflow

1. **Confirm artifacts.** `ls <output-dir>`. You need at least `TRIAGE.json`
   or `findings.json`. Missing optional files just omit their sections.

2. **Write `narrative.json`.** Summarize the prose the JSON can't carry, drawn
   *only* from `architecture.md`, `REPORT.md`, and `THREAT_MODEL.md` in the run
   directory — do not invent facts. All keys optional; the script falls back to
   "see <artifact>" text for any you omit. HTML is allowed in the `*_html`-style
   fields (`what_is.html`, `threat_highlights`, `exec_summary`, `highest_impact`,
   and each `does_well` / `trust_actors` entry) — use `<code>`, `<strong>`; the
   script does **not** escape those, so keep them well-formed. Plain-string
   fields (`tech_stack`, `attack_surfaces`, `focus_areas`) are escaped for you.

   ```json
   {
     "target_url": "https://github.com/org/repo",
     "date": "2026-07-02",
     "analysis_type": "Static analysis",
     "run_model": "claude-opus-4-8",
     "run_tokens": 1834219,
     "output_dir": "targets/repo/run-1",
     "scope_bar": "One-line scope bar (may include <code>…</code>).",
     "what_is": {"title": "What X is", "html": "<p>…</p>"},
     "tech_stack": ["TypeScript on Node 22", "SQLite via Kysely"],
     "trust_actors": ["<strong>A. Operator</strong> — …", "<strong>B. Node</strong> — …"],
     "attack_surfaces": ["Gateway HTTP/WS auth", "Webhook signature"],
     "threat_highlights": "<p>Derived threats T1–T20 …</p>",
     "focus_areas": ["ssrf", "webhook-replay", "approval-bypass"],
     "hunt_output": "<p><strong>11 candidate findings</strong> …</p>",
     "triage_method_note": "Optional method caveat rendered as a warn callout.",
     "exec_summary": "<p>…</p>",
     "highest_impact": "F-001 — …",
     "does_well": ["Fail-closed dotenv blocklist", "SSRF guard with rebinding defense"]
   }
   ```

   `focus_areas` defaults to the distinct finding categories, and
   `attack_surfaces` may repeat them — that's fine. Omit `narrative.json`
   entirely and you still get a complete, if terse, report.

   **Run provenance:** `run_model` is the model the orchestrating agent ran
   the audit on (e.g. `claude-opus-4-8`, `glm-5.2`); `run_tokens` is the total
   token count for the run (int or numeric string — rendered with thousands
   separators). Both surface as header meta-cards. If `run_model` is omitted
   the report falls back to `TRIAGE.json`'s `triage_context.judge_model`; if
   `run_tokens` is omitted the card shows `—`. Record the actual model you're
   running under and the run's token usage if you know them — don't guess a
   number.

3. **Generate.**
   ```
   python3 .claude/skills/bughunt-audit-report/generate-report.py <output-dir>
   ```
   Writes `<output-dir>/index.html`. Non-zero exit means neither `TRIAGE.json`
   nor `findings.json` was found — fix the path.

4. **Report the path** to the user as a `file://<output-dir>/index.html` link.
   Do not open a browser or push anywhere.

## What the script owns vs. what you own

- **Script (never hand-edit the HTML):** header meta cards, stats bar, the
  Phase 2 hunt table, Phase 3 tallies/owner routing, patch cards, payload
  cards, and the final ranked findings table — all from the JSON. Counts are
  computed, not copied.
- **You (via `narrative.json`):** the recon story, threat-model highlights,
  executive summary, and "what the codebase does well". Keep it faithful to the
  markdown artifacts.

If you find yourself wanting to edit `index.html` directly to fix a number, the
number is wrong in `TRIAGE.json` — fix it there and re-run, so the machine and
human views stay reconciled.
