#!/usr/bin/env python3
"""Render a self-contained security-audit index.html from run artifacts.

Deterministic: every count, table row, and patch/payload card is derived from
the machine-readable artifacts in the output directory. Prose sections (recon
narrative, executive summary, "what the codebase does well") come from an
optional narrative.json the orchestrator writes by summarizing architecture.md
/ REPORT.md / THREAT_MODEL.md — never invented here.

Inputs (in <output-dir>, all optional except TRIAGE.json OR findings.json):
  TRIAGE.json    primary source: metadata, ranked findings, summary counts
  PATCHES.json   Phase 5 patch cards
  PAYLOADS.json  Phase 6 payload/PoC cards
  findings.json  schema-validated confirmed/rejected list (validation badge)
  narrative.json prose slots (see NARRATIVE_KEYS below)

Output: <output-dir>/index.html

Layout/CSS follows the reference template at
~/security-audit-skill/openclaw/run-1/index.html (dark theme, phase pipeline,
findings table, patch cards).

Usage: python3 generate-report.py <output-dir>
"""
import html
import json
import sys
from datetime import date
from pathlib import Path

SAST_TOOL_DEFS = [
    # (source_key, display_name, description, raw_filename)
    ("semgrep",          "Semgrep",          "SAST — pattern matching on source ASTs",         ".semgrep.json"),
    ("osv",              "osv-scanner",      "Known-vulnerable dependencies via OSV.dev",       ".osv.json"),
    ("grype",            "Grype",            "Container image & filesystem CVEs",               ".grype.json"),
    ("gitleaks",         "Gitleaks",         "Hardcoded secrets — working tree + git history",  ".gitleaks.json"),
    ("checkov",          "Checkov",          "IaC misconfig — Terraform, K8s, Docker, etc.",   ".checkov.json"),
    ("govulncheck",      "govulncheck",      "Go callgraph-reachable dependency CVEs",          ".govulncheck.json"),
    ("security_context", "Security Context", "Historical vuln leads from public GitHub history", None),
]

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "INFO": 4}
SEV_CLASS = {
    "CRITICAL": "sev-critical", "HIGH": "sev-high", "MEDIUM": "sev-medium",
    "LOW": "sev-low", "INFORMATIONAL": "sev-info", "INFO": "sev-info",
}
SEV_DOT = {
    "CRITICAL": "var(--critical)", "HIGH": "var(--high)", "MEDIUM": "var(--medium)",
    "LOW": "var(--low)", "INFORMATIONAL": "var(--info)", "INFO": "var(--info)",
}
OUTCOME_CLASS = {
    "exploitable": "exploitable", "exploitation_confirmed": "exploitable",
    "needs_manual_test": "needs-manual", "mitigated": "mitigated",
    "not_actionable": "rejected", "rejected": "rejected",
}

NARRATIVE_KEYS = (
    "analysis_type", "scope_bar", "what_is", "tech_stack", "trust_actors",
    "attack_surfaces", "threat_highlights", "focus_areas", "hunt_output",
    "triage_method_note", "exec_summary", "highest_impact", "does_well",
    "run_model", "run_tokens",
)


def _sast_raw_count(outdir, raw_file):
    """Count raw hits from a SAST tool output file in outdir. Returns int or None."""
    if raw_file is None:
        return None
    p = Path(outdir) / raw_file
    if not p.exists():
        return None
    if raw_file == ".govulncheck.json":
        count = 0
        try:
            for line in p.read_text().splitlines():
                line = line.strip()
                if line:
                    try:
                        obj = json.loads(line)
                        if obj.get("finding"):
                            count += 1
                    except (json.JSONDecodeError, ValueError):
                        pass
        except OSError:
            pass
        return count
    try:
        data = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if raw_file == ".semgrep.json":
        return len(data.get("results", []))
    if raw_file == ".osv.json":
        total = 0
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                total += len(pkg.get("vulnerabilities", []))
        return total
    if raw_file == ".grype.json":
        return len(data.get("matches", []))
    if raw_file == ".gitleaks.json":
        return len(data) if isinstance(data, list) else 0
    if raw_file == ".checkov.json":
        failed = []
        candidate = data.get("results") or data
        if isinstance(candidate, dict):
            failed = candidate.get("failed_checks", [])
        elif isinstance(candidate, list):
            for item in candidate:
                if isinstance(item, dict):
                    inner = item.get("results", {})
                    if isinstance(inner, dict):
                        failed.extend(inner.get("failed_checks", []))
        return len(failed)
    return None


def _sast_findings_table(src_findings):
    """Render a compact table of SAST-promoted findings (from VULN-FINDINGS.json)."""
    if not src_findings:
        return '<p style="color:var(--text-muted);font-size:.82rem;padding:.4rem 0">No findings promoted from this tool.</p>'
    rows = []
    for f in src_findings:
        loc = f"{f.get('file', '')}:{f.get('line', '')}" if f.get("file") else ""
        rows.append(
            f"<tr><td><strong>{esc(f.get('id', ''))}</strong></td>"
            f"<td>{sev_badge(f.get('severity'))}</td>"
            f"<td><code>{esc(loc)}</code></td>"
            f"<td>{esc(f.get('title') or f.get('category', ''))}</td></tr>"
        )
    return (
        '<div class="table-wrap" style="margin:.6rem 0 0"><table>'
        "<thead><tr><th>ID</th><th>Severity</th><th>Location</th><th>Title / Advisory</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def sast_evidence_section(vuln_doc, outdir):
    """Render the Deterministic Pre-Scan Evidence block for Phase 2."""
    if not vuln_doc:
        return ""
    summary = vuln_doc.get("summary", {})
    tools_used = summary.get("tools", {})
    by_source = summary.get("by_source", {})
    raw_hits_meta = summary.get("raw_hits", {})
    findings = vuln_doc.get("findings", [])

    sast_keys = {t[0] for t in SAST_TOOL_DEFS}
    by_src = {}
    for f in findings:
        src = f.get("source", "")
        if src in sast_keys:
            by_src.setdefault(src, []).append(f)

    tool_cards = []
    for key, name, desc, raw_file in SAST_TOOL_DEFS:
        used = tools_used.get(key, False) or bool(by_src.get(key))
        promoted = by_source.get(key, len(by_src.get(key, [])))
        raw_count = raw_hits_meta.get(key) if raw_hits_meta else None
        if raw_count is None:
            raw_count = _sast_raw_count(outdir, raw_file)

        if used:
            counts = []
            if raw_count is not None:
                counts.append(f'<span class="sast-count raw">{raw_count} raw hits</span>')
            if promoted:
                counts.append(f'<span class="sast-count promoted">{promoted} promoted</span>')
            elif raw_count is not None:
                counts.append('<span class="sast-count zero">0 promoted</span>')
            tool_cards.append(
                f'<div class="sast-card ran">'
                f'<span class="sast-card-name">{esc(name)}</span>'
                f'<span class="sast-card-desc">{esc(desc)}</span>'
                f'<div class="sast-card-counts">{"".join(counts)}</div>'
                f"</div>"
            )
        else:
            tool_cards.append(
                f'<div class="sast-card skipped">'
                f'<span class="sast-card-name">{esc(name)}</span>'
                f'<span class="sast-card-desc">{esc(desc)}</span>'
                f'<div class="sast-card-counts"><span class="sast-count skipped">not used</span></div>'
                f"</div>"
            )

    detail_blocks = []
    for key, name, desc, raw_file in SAST_TOOL_DEFS:
        src_findings = by_src.get(key, [])
        used = tools_used.get(key, False) or bool(src_findings)
        if not used:
            continue
        raw_count = raw_hits_meta.get(key) if raw_hits_meta else None
        if raw_count is None:
            raw_count = _sast_raw_count(outdir, raw_file)
        count_str = f"{raw_count} raw hits" if raw_count is not None else f"{len(src_findings)} promoted"
        detail_blocks.append(
            f'<details class="sast-detail">'
            f"<summary><strong>{esc(name)}</strong> &mdash; {esc(count_str)}</summary>"
            + _sast_findings_table(src_findings)
            + "</details>"
        )

    if not tool_cards:
        return ""

    return (
        '  <div id="sast-evidence" style="margin:1.5rem 0 2rem">\n'
        '    <h3 style="font-size:1rem;font-weight:700;color:var(--text);margin-bottom:.4rem;'
        'padding-bottom:.5rem;border-bottom:1px solid var(--border)">Deterministic Pre-Scan Evidence</h3>\n'
        '    <p style="color:var(--text-muted);font-size:.84rem;margin-bottom:1rem">'
        "Raw output from the deterministic scanner layer (Steps 0&ndash;0g). "
        "These hits seeded the subagent hunt; promoted findings appear in the candidate table below.</p>\n"
        '    <div class="sast-grid">\n'
        + "".join(f"      {c}\n" for c in tool_cards)
        + "    </div>\n"
        + "".join(f"    {b}\n" for b in detail_blocks)
        + "  </div>\n"
    )


def fmt_tokens(v):
    """Render a token count with thousands separators; pass through non-numeric."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, (int, float)):
        return f"{int(v):,}"
    s = str(v).strip()
    digits = s.replace(",", "").replace("_", "")
    if digits.isdigit():
        return f"{int(digits):,}"
    return s


def esc(s):
    return html.escape(str(s), quote=True)


def load(d, name):
    p = Path(d) / name
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def norm_finding_id(fid):
    """Normalize f001 / F-001 / F001 to the same key for cross-artifact joins."""
    return (fid or "").upper().replace("-", "")


def resolve_severity(f):
    """Severity from triage row, vuln-scan row, or findings.json object."""
    for key in ("derived_severity", "severity_label", "claimed_severity"):
        v = f.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().upper()
    sev = f.get("severity")
    if isinstance(sev, str) and sev.strip():
        return sev.strip().upper()
    if isinstance(sev, dict):
        overall = sev.get("overall_severity")
        if isinstance(overall, str) and overall.strip():
            return overall.strip().upper()
    return "INFO"


def resolve_verdict(f):
    """TRUE_POSITIVE / FALSE_POSITIVE from triage variants."""
    v = f.get("verifier_verdict") or f.get("verdict") or ""
    return str(v).upper().replace("-", "_")


def resolve_verify_outcome(f):
    """exploitable / needs_manual_test from triage variants."""
    return f.get("verify_outcome") or f.get("verify_verdict") or ""


def resolve_first_link(f):
    links = f.get("first_links")
    if isinstance(links, list) and links:
        return links[0]
    return f.get("first_link") or ""


def normalize_finding(f):
    """Unify field names expected by render helpers."""
    row = dict(f)
    row["derived_severity"] = resolve_severity(row)
    row["verifier_verdict"] = resolve_verdict(row)
    row["verify_outcome"] = resolve_verify_outcome(row)
    link = resolve_first_link(row)
    if link:
        row["first_link"] = link
    return row


def sev_badge(sev):
    sev = (sev or "INFO").upper()
    return f'<span class="sev {SEV_CLASS.get(sev, "sev-info")}">{esc(sev)}</span>'


def outcome_badge(outcome):
    cls = OUTCOME_CLASS.get(outcome, "")
    label = (outcome or "").replace("_", " ")
    return f'<span class="outcome {cls}">{esc(label)}</span>'


CSS = """
    :root {
      --bg:#0d1117; --bg-elevated:#161b22; --bg-card:#1c2128; --border:#30363d;
      --text:#e6edf3; --text-muted:#8b949e; --accent:#58a6ff; --accent-dim:#1f3a5f;
      --critical:#ff6b6b; --high:#f0883e; --medium:#d29922; --low:#3fb950; --info:#8b949e;
      --phase-1:#a371f7; --phase-2:#f778ba; --phase-3:#79c0ff; --phase-4:#56d364;
      --phase-5:#ffa657; --phase-6:#e3b341;
      --font:"Segoe UI",system-ui,-apple-system,sans-serif;
      --mono:"Cascadia Code","Fira Code","Consolas",monospace;
      --radius:10px; --shadow:0 4px 24px rgba(0,0,0,.35);
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html{scroll-behavior:smooth}
    body{font-family:var(--font);background:var(--bg);color:var(--text);line-height:1.6;font-size:15px}
    header{background:linear-gradient(135deg,#161b22 0%,#0d1117 60%,#1a1f2e 100%);border-bottom:1px solid var(--border);padding:2.5rem 2rem 2rem}
    .header-inner{max-width:1100px;margin:0 auto}
    .badge-row{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}
    .badge{display:inline-block;padding:.2rem .65rem;border-radius:999px;font-size:.75rem;font-weight:600;letter-spacing:.03em;text-transform:uppercase;border:1px solid var(--border);background:var(--bg-elevated);color:var(--text-muted)}
    h1{font-size:clamp(1.6rem,4vw,2.2rem);font-weight:700;letter-spacing:-.02em;margin-bottom:.4rem}
    h1 span{color:var(--accent)}
    .subtitle{color:var(--text-muted);font-size:.95rem;max-width:70ch}
    .meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-top:1.5rem}
    .meta-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:.9rem 1.1rem}
    .meta-card .label{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin-bottom:.25rem}
    .meta-card .value{font-weight:600;font-size:.95rem}
    .meta-card .value.big{font-size:1.6rem;font-weight:700}
    .meta-card.high .value.big{color:var(--high)}
    .meta-card.critical .value.big{color:var(--critical)}
    nav{position:sticky;top:0;z-index:100;background:rgba(13,17,23,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
    nav ul{max-width:1100px;margin:0 auto;list-style:none;display:flex;flex-wrap:wrap;gap:0;padding:0 1rem}
    nav a{display:block;padding:.75rem 1rem;color:var(--text-muted);text-decoration:none;font-size:.85rem;font-weight:500;border-bottom:2px solid transparent;transition:color .15s,border-color .15s}
    nav a:hover{color:var(--text);border-color:var(--accent)}
    main{max-width:1100px;margin:0 auto;padding:2rem 1.5rem 4rem}
    .pipeline{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:2.5rem;align-items:center;justify-content:center}
    .pipeline-step{display:flex;align-items:center;gap:.5rem;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:.55rem 1rem;font-size:.82rem;font-weight:600;text-decoration:none;color:var(--text);transition:transform .15s,border-color .15s}
    .pipeline-step:hover{transform:translateY(-2px);border-color:var(--accent)}
    .pipeline-step .num{width:1.6rem;height:1.6rem;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.75rem;font-weight:700;color:#fff;flex-shrink:0}
    .pipeline-step.p1 .num{background:var(--phase-1)}
    .pipeline-step.p2 .num{background:var(--phase-2)}
    .pipeline-step.p3 .num{background:var(--phase-3)}
    .pipeline-step.p4 .num{background:var(--phase-4)}
    .pipeline-step.p5 .num{background:var(--phase-5)}
    .pipeline-step.p6 .num{background:var(--phase-6)}
    .pipeline-arrow{color:var(--text-muted);font-size:1.1rem}
    section{margin-bottom:3rem;scroll-margin-top:3.5rem}
    .phase-header{display:flex;align-items:flex-start;gap:1rem;margin-bottom:1.25rem;padding-bottom:1rem;border-bottom:1px solid var(--border)}
    .phase-num{width:2.5rem;height:2.5rem;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:1rem;color:#fff;flex-shrink:0}
    .phase-header h2{font-size:1.35rem;font-weight:700;letter-spacing:-.01em}
    .phase-header .phase-sub{color:var(--text-muted);font-size:.88rem;margin-top:.15rem}
    .phase-header .artifact{font-family:var(--mono);font-size:.78rem;color:var(--accent);margin-top:.35rem}
    .card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem 1.4rem;margin-bottom:1rem;box-shadow:var(--shadow)}
    .card h3{font-size:.95rem;font-weight:600;margin-bottom:.6rem;color:var(--text)}
    .card p,.card li{color:var(--text-muted);font-size:.9rem}
    .card ul,.card ol{padding-left:1.25rem;margin-top:.4rem}
    .card li{margin-bottom:.3rem}
    .grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}
    .grid-3{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem}
    .sev{display:inline-block;padding:.15rem .55rem;border-radius:4px;font-size:.72rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
    .sev-critical{background:rgba(255,107,107,.15);color:var(--critical);border:1px solid rgba(255,107,107,.3)}
    .sev-high{background:rgba(240,136,62,.15);color:var(--high);border:1px solid rgba(240,136,62,.3)}
    .sev-medium{background:rgba(210,153,34,.15);color:var(--medium);border:1px solid rgba(210,153,34,.3)}
    .sev-low{background:rgba(63,185,80,.15);color:var(--low);border:1px solid rgba(63,185,80,.3)}
    .sev-info{background:rgba(139,148,158,.15);color:var(--info);border:1px solid rgba(139,148,158,.3)}
    .outcome{display:inline-block;padding:.12rem .5rem;border-radius:4px;font-size:.72rem;font-weight:600;background:var(--bg-elevated);border:1px solid var(--border);color:var(--text-muted)}
    .outcome.exploitable{color:#ff7b72;border-color:rgba(255,123,114,.3)}
    .outcome.needs-manual{color:var(--medium);border-color:rgba(210,153,34,.3)}
    .outcome.mitigated{color:var(--low);border-color:rgba(63,185,80,.3)}
    .outcome.rejected{color:var(--info)}
    .table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1rem}
    table{width:100%;border-collapse:collapse;font-size:.85rem}
    thead{background:var(--bg-elevated)}
    th{text-align:left;padding:.7rem 1rem;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted);border-bottom:1px solid var(--border);white-space:nowrap}
    td{padding:.65rem 1rem;border-bottom:1px solid var(--border);vertical-align:top;color:var(--text-muted)}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:rgba(88,166,255,.04)}
    td code,.mono{font-family:var(--mono);font-size:.78rem;color:var(--accent);word-break:break-all}
    td strong{color:var(--text);font-weight:600}
    .tags{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}
    .tag{background:var(--accent-dim);color:var(--accent);border:1px solid rgba(88,166,255,.25);border-radius:4px;padding:.2rem .55rem;font-size:.75rem;font-weight:500}
    .patch-card{background:var(--bg-card);border:1px solid var(--border);border-left:3px solid var(--phase-5);border-radius:var(--radius);padding:1rem 1.2rem;margin-bottom:.75rem}
    .patch-card .patch-id{font-family:var(--mono);font-size:.78rem;color:var(--phase-5);font-weight:600}
    .patch-card h4{font-size:.9rem;margin:.3rem 0 .4rem;color:var(--text)}
    .patch-card p{font-size:.83rem;color:var(--text-muted)}
    .patch-card .files{font-family:var(--mono);font-size:.75rem;color:var(--accent);margin-top:.4rem}
    .payload-card{background:var(--bg-card);border:1px solid var(--border);border-left:3px solid var(--phase-6);border-radius:var(--radius);padding:1rem 1.2rem;margin-bottom:.75rem}
    .payload-card .payload-id{font-family:var(--mono);font-size:.78rem;color:var(--phase-6);font-weight:600}
    .payload-card h4{font-size:.9rem;margin:.3rem 0 .4rem;color:var(--text)}
    .payload-card p{font-size:.83rem;color:var(--text-muted)}
    .payload-card pre{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:.7rem .9rem;margin:.5rem 0;overflow-x:auto;font-family:var(--mono);font-size:.76rem;color:var(--text);white-space:pre-wrap;word-break:break-word}
    .payload-card .meta{font-size:.76rem;color:var(--text-muted);margin-top:.35rem}
    .payload-card .meta b{color:var(--text)}
    .callout{border-left:3px solid var(--accent);background:var(--accent-dim);border-radius:0 var(--radius) var(--radius) 0;padding:.9rem 1.1rem;margin:1rem 0;font-size:.88rem;color:var(--text-muted)}
    .callout.warn{border-color:var(--medium);background:rgba(210,153,34,.08)}
    .callout strong{color:var(--text)}
    .stats-bar{display:flex;flex-wrap:wrap;gap:.75rem;margin:1rem 0}
    .stat-pill{display:flex;align-items:center;gap:.5rem;background:var(--bg-elevated);border:1px solid var(--border);border-radius:999px;padding:.4rem .9rem;font-size:.82rem}
    .stat-pill .dot{width:.55rem;height:.55rem;border-radius:50%}
    footer{border-top:1px solid var(--border);padding:1.5rem 2rem;text-align:center;color:var(--text-muted);font-size:.8rem}
    footer a{color:var(--accent);text-decoration:none}
    footer a:hover{text-decoration:underline}
    .sast-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:.7rem;margin:0 0 1.1rem}
    .sast-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:.9rem 1rem;display:flex;flex-direction:column;gap:.3rem}
    .sast-card.ran{border-left:3px solid var(--low)}
    .sast-card.skipped{opacity:.5}
    .sast-card-name{font-weight:700;font-size:.85rem;color:var(--text)}
    .sast-card-desc{font-size:.74rem;color:var(--text-muted);line-height:1.4}
    .sast-card-counts{display:flex;gap:.4rem;flex-wrap:wrap;margin-top:.2rem}
    .sast-count{font-size:.71rem;font-weight:600;padding:.13rem .4rem;border-radius:4px}
    .sast-count.raw{background:rgba(88,166,255,.12);color:var(--accent);border:1px solid rgba(88,166,255,.25)}
    .sast-count.promoted{background:rgba(63,185,80,.12);color:var(--low);border:1px solid rgba(63,185,80,.25)}
    .sast-count.zero{background:var(--bg-elevated);color:var(--text-muted);border:1px solid var(--border)}
    .sast-count.skipped{background:var(--bg-elevated);color:var(--text-muted);border:1px solid var(--border)}
    details.sast-detail{margin-bottom:.75rem;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:.7rem 1rem}
    details.sast-detail summary{cursor:pointer;font-size:.87rem;color:var(--text);display:flex;align-items:center;gap:.5rem;list-style:none;user-select:none}
    details.sast-detail summary::-webkit-details-marker{display:none}
    details.sast-detail summary::after{content:"▾";margin-left:auto;color:var(--text-muted);font-size:.78rem;transition:transform .15s}
    details.sast-detail[open] summary::after{transform:rotate(-180deg)}
    details.sast-detail .table-wrap{margin-top:.7rem}
    @media (max-width:600px){.pipeline-arrow{display:none}header{padding:1.5rem 1rem}main{padding:1.5rem 1rem 3rem}}
"""


def render(outdir):
    triage = load(outdir, "TRIAGE.json") or {}
    vuln_doc = load(outdir, "VULN-FINDINGS.json") or {}
    vuln_by_id = {}
    for f in vuln_doc.get("findings", []):
        fid = f.get("id")
        if fid:
            vuln_by_id[norm_finding_id(fid)] = f
    patches_doc = load(outdir, "PATCHES.json") or {}
    payloads_doc = load(outdir, "PAYLOADS.json") or {}
    findings_json = load(outdir, "findings.json")
    narr = load(outdir, "narrative.json") or {}

    # findings.json confirmed entries keyed by title for severity fallback
    confirmed_by_title = {}
    if isinstance(findings_json, list):
        for cf in findings_json:
            if cf.get("verdict") == "confirmed" and cf.get("title"):
                confirmed_by_title[cf["title"]] = cf

    findings = []
    for f in triage.get("findings", []):
        row = dict(f)
        vf = vuln_by_id.get(norm_finding_id(row.get("id")))
        if vf:
            for key in ("title", "category", "file", "line", "description", "severity"):
                row.setdefault(key, vf.get(key))
            if not resolve_first_link(row) and vf.get("file"):
                row.setdefault("first_link", f"{vf['file']}:{vf.get('line', '')}")
        if not resolve_severity(row) or resolve_severity(row) == "INFO":
            cf = confirmed_by_title.get(row.get("title", ""))
            if cf:
                row.setdefault("severity", cf.get("severity"))
        findings.append(normalize_finding(row))
    summary = triage.get("summary", {})
    target = triage.get("target") or narr.get("target") or Path(outdir).parent.name
    run = triage.get("run") or narr.get("run") or Path(outdir).name
    run_date = narr.get("date") or date.today().isoformat()
    analysis_type = narr.get("analysis_type", "Static analysis")

    by_sev = summary.get("by_severity", {})
    by_outcome = summary.get("by_verify_outcome", {})
    tp = summary.get(
        "true_positives",
        summary.get(
            "true_positive",
            sum(1 for f in findings if f.get("verifier_verdict") == "TRUE_POSITIVE"),
        ),
    )
    fp = summary.get(
        "false_positives",
        summary.get(
            "false_positive",
            sum(1 for f in findings if f.get("verifier_verdict") == "FALSE_POSITIVE"),
        ),
    )

    # highest severity present among true positives
    highest = None
    for f in findings:
        if f.get("verifier_verdict") != "TRUE_POSITIVE":
            continue
        s = (f.get("derived_severity") or "").upper()
        if s in SEV_ORDER and (highest is None or SEV_ORDER[s] < SEV_ORDER[highest]):
            highest = s
    highest_count = sum(1 for f in findings if (f.get("derived_severity") or "").upper() == highest and f.get("verifier_verdict") == "TRUE_POSITIVE") if highest else 0
    highest_label = f"{highest_count} {highest}" if highest else "—"
    highest_cls = "critical" if highest == "CRITICAL" else ("high" if highest == "HIGH" else "")

    patches = patches_doc.get("patches", [])
    payloads = payloads_doc.get("payloads", [])

    # ---- header ----
    validated = ""
    if isinstance(findings_json, list) and findings_json:
        validated = '<span class="badge">findings.json validated ✓</span>'
    target_url = narr.get("target_url")
    target_html = f'<a href="{esc(target_url)}" style="color:var(--accent);text-decoration:none">{esc(target)}</a>' if target_url else esc(target)
    outdir_disp = narr.get("output_dir", str(outdir))

    # Run provenance: the model the orchestrating agent ran on, and total tokens.
    # Prefer explicit narrative values; fall back to the triage panel's judge
    # model when the run model wasn't recorded separately.
    triage_ctx = triage.get("triage_context") or {}
    run_model = narr.get("run_model") or triage_ctx.get("run_model") or triage_ctx.get("judge_model") or "—"
    tokens_disp = fmt_tokens(narr.get("run_tokens") if narr.get("run_tokens") is not None else triage_ctx.get("run_tokens")) or "—"

    parts = [f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Audit — {esc(target)} ({esc(run)})</title>
  <style>{CSS}</style>
</head>
<body>
<header>
  <div class="header-inner">
    <div class="badge-row">
      <span class="badge">{esc(analysis_type)}</span>
      <span class="badge">{esc(run)}</span>
      <span class="badge">{esc(run_date)}</span>
      {validated}
    </div>
    <h1>Security Audit — <span>{esc(target)}</span></h1>
    <p class="subtitle">Complete audit pipeline: recon &amp; threat model → hunt → validate → report → patch → payloads.
      Methodology: Cloudflare security-audit (MIT) + Anthropic defending-code pipeline (Apache-2.0).</p>
    <div class="meta-grid">
      <div class="meta-card"><div class="label">Target</div><div class="value">{target_html}</div></div>
      <div class="meta-card"><div class="label">Confirmed findings</div><div class="value big">{tp}</div></div>
      <div class="meta-card {highest_cls}"><div class="label">Highest severity</div><div class="value big">{esc(highest_label)}</div></div>
      <div class="meta-card"><div class="label">Patches (inert)</div><div class="value big">{len(patches)}</div></div>
      <div class="meta-card"><div class="label">Test payloads</div><div class="value big">{len(payloads)}</div></div>
      <div class="meta-card"><div class="label">Model</div><div class="value">{esc(run_model)}</div></div>
      <div class="meta-card"><div class="label">Tokens used</div><div class="value big">{esc(tokens_disp)}</div></div>
      <div class="meta-card"><div class="label">Output directory</div><div class="value" style="font-family:var(--mono);font-size:.8rem">{esc(outdir_disp)}</div></div>
    </div>
  </div>
</header>
<nav><ul>
  <li><a href="#overview">Overview</a></li>
  <li><a href="#phase-1">Phase 1 — Recon</a></li>
  <li><a href="#phase-2">Phase 2 — Hunt</a></li>
  <li><a href="#sast-evidence">SAST Evidence</a></li>
  <li><a href="#phase-3">Phase 3 — Validate</a></li>
  <li><a href="#phase-4">Phase 4 — Report</a></li>
  <li><a href="#phase-5">Phase 5 — Patch</a></li>
  <li><a href="#phase-6">Phase 6 — Payloads</a></li>
  <li><a href="#findings-table">All findings</a></li>
</ul></nav>
<main>
  <div class="pipeline" id="overview">
    <a class="pipeline-step p1" href="#phase-1"><span class="num">1</span> Recon → threat model</a>
    <span class="pipeline-arrow">→</span>
    <a class="pipeline-step p2" href="#phase-2"><span class="num">2</span> Hunt → vuln-scan</a>
    <span class="pipeline-arrow">→</span>
    <a class="pipeline-step p3" href="#phase-3"><span class="num">3</span> Validate → triage</a>
    <span class="pipeline-arrow">→</span>
    <a class="pipeline-step p4" href="#phase-4"><span class="num">4</span> Report → findings.json</a>
    <span class="pipeline-arrow">→</span>
    <a class="pipeline-step p5" href="#phase-5"><span class="num">5</span> Patch → inert diffs</a>
    <span class="pipeline-arrow">→</span>
    <a class="pipeline-step p6" href="#phase-6"><span class="num">6</span> Payloads → PoCs</a>
  </div>
"""]

    # ---- scope callout ----
    scope = narr.get("scope_bar") or triage.get("scope_bar")
    if scope:
        parts.append(f'  <div class="callout"><strong>Scope bar:</strong> {scope if narr.get("scope_bar") else esc(scope)}</div>\n')

    # ---- stats bar ----
    pills = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        n = by_sev.get(sev, 0)
        if n:
            pills.append(f'<div class="stat-pill"><span class="dot" style="background:{SEV_DOT[sev]}"></span> {n} {sev}</div>')
    if fp:
        pills.append(f'<div class="stat-pill"><span class="dot" style="background:var(--info)"></span> {fp} rejected</div>')
    for key, label, color in (("exploitable", "exploitable", "var(--phase-3)"),
                              ("needs_manual_test", "needs manual test", "var(--phase-6)"),
                              ("mitigated", "mitigated", "var(--low)")):
        n = by_outcome.get(key, 0)
        if n:
            pills.append(f'<div class="stat-pill"><span class="dot" style="background:{color}"></span> {n} {label}</div>')
    if pills:
        parts.append('  <div class="stats-bar">\n    ' + "\n    ".join(pills) + "\n  </div>\n")

    # ---- Phase 1 recon ----
    parts.append(phase_recon(narr))
    # ---- Phase 2 hunt ----
    parts.append(phase_hunt(narr, findings, vuln_doc, outdir))
    # ---- Phase 3 validate ----
    parts.append(phase_validate(narr, findings, summary, tp, fp))
    # ---- Phase 4 report ----
    parts.append(phase_report(narr, findings_json, tp, fp))
    # ---- Phase 5 patch ----
    parts.append(phase_patch(patches_doc, patches))
    # ---- Phase 6 payloads ----
    parts.append(phase_payloads(payloads_doc, payloads))
    # ---- full table ----
    parts.append(findings_table(findings))

    parts.append(f"""</main>
<footer>
  Security audit {esc(run)} · {esc(target)} · {esc(run_date)}<br>
  Methodology: Cloudflare security-audit (MIT) · Anthropic defending-code pipeline (Apache-2.0)<br>
  Artifacts: <code>{esc(outdir_disp)}</code>
</footer>
</body>
</html>
""")
    return "".join(parts)


def _list_items(items):
    return "\n".join(f"          <li>{it}</li>" for it in items)


def phase_recon(narr):
    what = narr.get("what_is") or {}
    what_title = esc(what.get("title", "What this codebase is"))
    what_html = what.get("html") or "<p>See <code>architecture.md</code> for the recon summary.</p>"
    stack = narr.get("tech_stack") or []
    actors = narr.get("trust_actors") or []
    surfaces = narr.get("attack_surfaces") or []
    threat_hi = narr.get("threat_highlights") or "See <code>THREAT_MODEL.md</code> for the full derived threat model."
    stack_html = _list_items([esc(s) for s in stack]) or "          <li>See <code>architecture.md</code></li>"
    actors_html = "\n".join(f"          <li>{a}</li>" for a in actors) or "          <li>See <code>THREAT_MODEL.md</code></li>"
    surfaces_html = "\n".join(f'          <span class="tag">{esc(s)}</span>' for s in surfaces)
    surfaces_block = f'      <div class="tags">\n{surfaces_html}\n      </div>' if surfaces else "<p>See <code>architecture.md</code>.</p>"
    return f"""  <section id="phase-1">
    <div class="phase-header">
      <div class="phase-num" style="background:var(--phase-1)">1</div>
      <div><h2>Recon → Threat Model</h2>
        <div class="phase-sub">Map architecture, trust boundaries, and input surfaces</div>
        <div class="artifact">Artifacts: architecture.md · THREAT_MODEL.md</div></div>
    </div>
    <div class="grid-2">
      <div class="card"><h3>{what_title}</h3>{what_html}</div>
      <div class="card"><h3>Tech stack</h3><ul>
{stack_html}
        </ul></div>
    </div>
    <div class="card"><h3>Trust model — actors</h3><ul>
{actors_html}
      </ul></div>
    <div class="card"><h3>Key attack surfaces</h3>
{surfaces_block}
    </div>
    <div class="card"><h3>Threat model highlights</h3><p>{threat_hi}</p></div>
  </section>
"""


def phase_hunt(narr, findings, vuln_doc=None, outdir=None):
    focus = narr.get("focus_areas") or sorted({f.get("category", "") for f in findings if f.get("category")})
    focus_html = "\n".join(f'          <span class="tag">{esc(s)}</span>' for s in focus)
    hunt_out = narr.get("hunt_output") or f"<p><strong style=\"color:var(--text)\">{len(findings)} candidate findings</strong> produced for validation.</p>"
    rows = []
    for f in findings:
        rows.append(
            f"          <tr><td><strong>{esc(f.get('id',''))}</strong></td>"
            f"<td>{sev_badge(f.get('derived_severity'))}</td>"
            f"<td>{esc(f.get('category',''))}</td>"
            f"<td>{esc(f.get('title',''))}</td></tr>"
        )
    rows_html = "\n".join(rows)
    sast_html = sast_evidence_section(vuln_doc, outdir) if vuln_doc else ""
    return f"""  <section id="phase-2">
    <div class="phase-header">
      <div class="phase-num" style="background:var(--phase-2)">2</div>
      <div><h2>Hunt → Vuln-Scan</h2>
        <div class="phase-sub">Deterministic pre-scans + parallel review subagents per focus area</div>
        <div class="artifact">Artifacts: VULN-FINDINGS.json · VULN-FINDINGS.md</div></div>
    </div>
    <div class="grid-2">
      <div class="card"><h3>Focus areas hunted</h3><div class="tags">
{focus_html}
      </div></div>
      <div class="card"><h3>Output</h3>{hunt_out}</div>
    </div>
{sast_html}    <div class="table-wrap"><table>
      <thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Title</th></tr></thead>
      <tbody>
{rows_html}
      </tbody>
    </table></div>
  </section>
"""


def phase_validate(narr, findings, summary, tp, fp):
    by_outcome = summary.get("by_verify_outcome", {})
    dupes = summary.get("duplicates_collapsed", summary.get("duplicates", 0))
    # group ids by outcome
    outcome_ids = {}
    for f in findings:
        outcome_ids.setdefault(f.get("verify_outcome", ""), []).append(f.get("id", ""))
    outcome_lines = []
    for key in ("exploitable", "exploitation_confirmed", "needs_manual_test", "mitigated", "not_actionable"):
        if outcome_ids.get(key):
            outcome_lines.append(f"          <li>{outcome_badge(key)} — {esc(', '.join(outcome_ids[key]))}</li>")
    outcome_html = "\n".join(outcome_lines)
    # owners
    owners = summary.get("owners") or {}
    if not owners:
        for f in findings:
            o = f.get("owner")
            if o and o != "—":
                owners[o] = owners.get(o, 0) + 1
    owner_ids = {}
    for f in findings:
        o = f.get("owner")
        if o and o != "—":
            owner_ids.setdefault(o, []).append(f.get("id", ""))
    owner_html = "\n".join(f"          <li><code>{esc(o)}</code> — {esc(', '.join(ids))}</li>" for o, ids in owner_ids.items())
    method = narr.get("triage_method_note")
    method_html = f'    <div class="callout warn"><strong>Method note:</strong> {method}</div>\n' if method else ""
    return f"""  <section id="phase-3">
    <div class="phase-header">
      <div class="phase-num" style="background:var(--phase-3)">3</div>
      <div><h2>Validate → Triage</h2>
        <div class="phase-sub">Adversarially verify each finding; deduplicate, re-rank, route to owners</div>
        <div class="artifact">Artifacts: TRIAGE.json · TRIAGE.md</div></div>
    </div>
{method_html}    <div class="grid-3">
      <div class="card"><h3>Verdict tally</h3><ul>
          <li><strong style="color:var(--low)">TRUE_POSITIVE:</strong> {tp}</li>
          <li><strong style="color:var(--info)">FALSE_POSITIVE:</strong> {fp}</li>
          <li>Duplicates collapsed: {dupes}</li>
        </ul></div>
      <div class="card"><h3>By verify outcome</h3><ul>
{outcome_html}
      </ul></div>
      <div class="card"><h3>Owner routing</h3><ul>
{owner_html}
      </ul></div>
    </div>
  </section>
"""


def phase_report(narr, findings_json, tp, fp):
    exec_summary = narr.get("exec_summary") or "<p>See <code>REPORT.md</code> for the executive summary.</p>"
    highest = narr.get("highest_impact")
    highest_html = f'<p style="margin-top:.5rem"><strong style="color:var(--text)">Highest impact:</strong> {highest}</p>' if highest else ""
    does_well = narr.get("does_well") or []
    dw_html = "\n".join(f"          <li>{d}</li>" for d in does_well) or "          <li>See <code>REPORT.md</code></li>"
    if isinstance(findings_json, list) and findings_json:
        total = len(findings_json)
        valid = f'<strong style="color:var(--low)">PASS — {total} findings valid</strong> ({tp} confirmed + {fp} rejected).'
    else:
        valid = "findings.json not present in this run."
    return f"""  <section id="phase-4">
    <div class="phase-header">
      <div class="phase-num" style="background:var(--phase-4)">4</div>
      <div><h2>Report → findings.json</h2>
        <div class="phase-sub">Machine-readable confirmed findings validated against report-schema.json</div>
        <div class="artifact">Artifacts: REPORT.md · FINDINGS-DETAIL.md · findings.json</div></div>
    </div>
    <div class="card"><h3>Executive summary</h3>{exec_summary}{highest_html}</div>
    <div class="grid-2">
      <div class="card"><h3>Schema validation</h3><p><code>node validate-findings.cjs findings.json</code></p>
        <p style="margin-top:.4rem">{valid}</p></div>
      <div class="card"><h3>What the codebase does well</h3><ul>
{dw_html}
      </ul></div>
    </div>
  </section>
"""


def phase_patch(patches_doc, patches):
    warn = patches_doc.get("warning") or "Patches are inert candidate diffs. Review each finding's notes, validate against tests, and resolve documented follow-ups before merging."
    cards = []
    for p in patches:
        files = p.get("files") or []
        files_disp = ", ".join(files) if isinstance(files, list) else str(files)
        cards.append(f"""    <div class="patch-card">
      <div class="patch-id">{esc(p.get('bug',''))} · {esc(p.get('finding',''))} · {sev_badge(p.get('severity'))}</div>
      <h4>{esc(p.get('title',''))}</h4>
      <p>{esc(p.get('summary') or p.get('notes',''))}</p>
      <div class="files">{esc(files_disp)}</div>
    </div>""")
    body = "\n".join(cards) if cards else '    <div class="card"><p>No patches generated for this run.</p></div>'
    return f"""  <section id="phase-5">
    <div class="phase-header">
      <div class="phase-num" style="background:var(--phase-5)">5</div>
      <div><h2>Patch → Inert Diffs</h2>
        <div class="phase-sub">Candidate fixes for human review — do not apply automatically</div>
        <div class="artifact">Artifacts: PATCHES/ · PATCHES.md · PATCHES.json</div></div>
    </div>
    <div class="callout warn"><strong>Warning:</strong> {esc(warn)}</div>
{body}
  </section>
"""


def phase_payloads(payloads_doc, payloads):
    warn = payloads_doc.get("warning") or "Payloads are for authorized testing against a controlled instance only. Each targets a confirmed finding; run in an isolated environment, never against third-party systems."
    cards = []
    for p in payloads:
        pid = f"{esc(p.get('finding',''))} · {esc(p.get('type',''))}"
        payload_txt = p.get("payload", "")
        harness = p.get("harness") or p.get("instructions")
        if isinstance(harness, list):
            harness = "; ".join(harness)
        expected = p.get("expected") or p.get("expected_result", "")
        meta = []
        if harness:
            meta.append(f"<b>Run:</b> {esc(harness)}")
        if expected:
            meta.append(f"<b>Expected:</b> {esc(expected)}")
        meta_html = ("<div class=\"meta\">" + "<br>".join(meta) + "</div>") if meta else ""
        cards.append(f"""    <div class="payload-card">
      <div class="payload-id">{pid} · {sev_badge(p.get('severity'))}</div>
      <h4>{esc(p.get('title',''))}</h4>
      <pre>{esc(payload_txt)}</pre>
      {meta_html}
    </div>""")
    body = "\n".join(cards) if cards else '    <div class="card"><p>No payloads generated for this run.</p></div>'
    return f"""  <section id="phase-6">
    <div class="phase-header">
      <div class="phase-num" style="background:var(--phase-6)">6</div>
      <div><h2>Payloads → Proof-of-Concept</h2>
        <div class="phase-sub">Runnable test inputs for each confirmed finding — authorized testing only</div>
        <div class="artifact">Artifacts: PAYLOADS.md · PAYLOADS.json</div></div>
    </div>
    <div class="callout warn"><strong>Authorized use only:</strong> {esc(warn)}</div>
{body}
  </section>
"""


def findings_table(findings):
    rows = []
    for f in findings:
        rejected = f.get("verifier_verdict") == "FALSE_POSITIVE"
        style = ' style="opacity:.7"' if rejected else ""
        loc = f.get("first_link") or (f"{f.get('file','')}:{f.get('line','')}" if f.get("file") else "")
        rows.append(f"""          <tr{style}>
            <td>{esc(f.get('rank',''))}</td>
            <td><strong>{esc(f.get('id',''))}</strong></td>
            <td>{sev_badge(f.get('derived_severity'))}</td>
            <td>{outcome_badge(f.get('verify_outcome'))}</td>
            <td>{esc(f.get('verifier_verdict',''))}</td>
            <td><code>{esc(loc)}</code></td>
            <td>{esc(f.get('title',''))}</td>
            <td>{esc(f.get('owner','—'))}</td>
          </tr>""")
    rows_html = "\n".join(rows)
    return f"""  <section id="findings-table">
    <div class="phase-header">
      <div class="phase-num" style="background:var(--accent)">∑</div>
      <div><h2>All Findings — Final Ranked Table</h2>
        <div class="phase-sub">Post-triage confirmed + rejected · reconciled to shared severity rubric</div></div>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>Rank</th><th>ID</th><th>Severity</th><th>Outcome</th><th>Verdict</th><th>Location</th><th>Title</th><th>Owner</th></tr></thead>
      <tbody>
{rows_html}
      </tbody>
    </table></div>
  </section>
"""


def main():
    if len(sys.argv) != 2:
        print("usage: python3 generate-report.py <output-dir>", file=sys.stderr)
        return 2
    outdir = Path(sys.argv[1]).expanduser()
    if not outdir.is_dir():
        print(f"error: not a directory: {outdir}", file=sys.stderr)
        return 2
    if not (outdir / "TRIAGE.json").exists() and not (outdir / "findings.json").exists():
        print(f"error: need TRIAGE.json or findings.json in {outdir}", file=sys.stderr)
        return 2
    out = outdir / "index.html"
    out.write_text(render(outdir))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
