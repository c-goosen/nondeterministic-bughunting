# nondeterministic-bughunting

Using CLI agentic tools to bughunt. Skills, code, etc.

## Security audit toolkit

This repo bundles an end-to-end, agentic security-audit pipeline under
[`.claude/skills/`](.claude/skills/). A single orchestrator skill,
[`security-audit`](.claude/skills/security-audit/SKILL.md), drives four staged
specialist skills and applies a manual-audit methodology at each phase:

```
threat-model  →  vuln-scan  →  triage  →  patch
   (recon)        (hunt)      (validate)  (fix)
```

| Phase | Methodology doc | Pipeline skill | Output |
|---|---|---|---|
| Recon | `RECONNAISSANCE.md` | `threat-model` | `THREAT_MODEL.md` |
| Hunt | `HUNTING.md`, `ATTACK-CLASSES.md` | `vuln-scan` | `VULN-FINDINGS.json` |
| Validate | `VALIDATION-AND-REPORTING.md` | `triage` | `TRIAGE.json` |
| Report | `report-schema.json`, `validate-findings.cjs` | — | `REPORT.md`, `findings.json` |
| Patch | — | `patch` | `PATCHES/` (inert diffs) |

Run it by invoking the `security-audit` skill against a target codebase.

### Deterministic pre-scan

The `vuln-scan` stage front-loads five external static scanners before the
LLM fan-out, so the agents start from real, reproducible signal:

- **[semgrep](https://github.com/semgrep/semgrep)** — pattern-based SAST.
- **[osv-scanner](https://github.com/google/osv-scanner)** — known-vulnerable
  dependencies via [OSV.dev](https://osv.dev).
- **[grype](https://github.com/anchore/grype)** — image/filesystem CVEs, run
  only when a Dockerfile is present.
- **[gitleaks](https://github.com/gitleaks/gitleaks)** — secrets in code and
  git history (always-on).
- **[checkov](https://github.com/bridgecrewio/checkov)** — infrastructure-as-code
  misconfig, run only when IaC (Terraform, k8s, CloudFormation, …) is present.

Install them once with:

```
bash .claude/skills/vuln-scan/setup-tools.sh
```

### Historical context (Security Context)

For targets that are public GitHub repos, `vuln-scan` and `triage` also
pull cached context from [Security Context](https://securitycontext.dev)
(`securitycontext.dev`) — a free, unauthenticated API/MCP service that
mines a repo's real fix-commit history and disclosed CVEs into recurring
weak spots and a ranked variant-lead backlog. It's a strong prior for
"where the next bug is most likely to surface" and is treated as advisory
context (leads to confirm/refute), never an auto-promoted finding. This is
best-effort and network-optional: non-GitHub targets, or an unreachable
service, just skip it. See [`securitycontext.dev/docs`](https://securitycontext.dev/docs)
for the full API/MCP surface.

### Test targets

`targets/` is an empty (gitignored) scratch directory for codebases you
want to point these skills at — see [`targets/README.md`](targets/README.md).

### Other agentic CLIs

`.opencode/skills` and `.cursor/skills` are symlinks to `.claude/skills`, so
the same skill set is available to OpenCode and Cursor as well.

Re-running the pipeline through the Cursor CLI agent with a non-Anthropic
model — e.g. **GLM 5.2** or **Kimi K2.7** — is recommended as a second pass:
the same skills prompted through a different model surface different
findings, which prevents single-model blind spots (and avoids burning
Claude usage on repeat scans). From the repo root:

```
cursor-agent --model glm-5.2  "Run the security-audit skill against targets/<repo>"
cursor-agent --model kimi-k2.7 "Run the security-audit skill against targets/<repo>"
```

(Model IDs follow whatever Cursor exposes in its `/model` picker — adjust
to the exact slug your Cursor version lists.) Diff the resulting
`VULN-FINDINGS.json` files, then feed the union into a single `/triage`
pass to dedupe and validate across models.

### Harness config

[`.claude/settings.json`](.claude/settings.json) pins the model and
pre-approves the read-only shell commands and scanner invocations the
pipeline needs (semgrep, osv-scanner, grype, gitleaks, checkov, `git`,
`gh api`, …), so an audit run doesn't stall on permission prompts.

## Sources

This toolkit is a combined work built from two upstream projects. Each retains
its own license — see [`NOTICES.md`](NOTICES.md) and [`LICENSES/`](LICENSES/).

- **[anthropics/defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)**
  — Apache-2.0. Provides the staged pipeline skills: `threat-model`, `vuln-scan`,
  `triage`, `patch`.
- **[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)**
  (`skills/security-audit`) — MIT. Provides the audit methodology:
  reconnaissance, hunting, attack classes, and validation & reporting.

The orchestrator glue (`.claude/skills/security-audit/SKILL.md`) is net-new and
MIT-licensed. See [`NOTICES.md`](NOTICES.md) for full attribution.

### Further reading

- Devansh, **[_Needle in the Haystack: LLMs for Vulnerability Research_](https://devansh.bearblog.dev/needle-in-the-haystack/)**
  — the "minimal scaffolding, maximal targeted exploration" methodology
  (thin-slice auditing, threat-modeling from CVE history, context-rot
  budgeting, and adversarial prompting) that informs how `threat-model` and
  `vuln-scan` are prompted. Credited as prior art in
  [`NOTICES.md`](NOTICES.md#5-methodology-references-prior-art-not-redistributed).
