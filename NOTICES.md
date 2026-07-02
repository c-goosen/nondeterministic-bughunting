# NOTICES

`nondeterministic-bughunting` is a combined work. The security tooling under
`.claude/skills/` is assembled from two upstream open-source projects, each of
which retains its own license. This file records what was used, where it came
from, and under which terms. Full license texts are in [`LICENSES/`](LICENSES/).

## Summary

| Component (in this repo) | Upstream source | License | Copyright |
|---|---|---|---|
| `.claude/skills/threat-model/` | anthropics/defending-code-reference-harness | Apache-2.0 | Anthropic PBC, 2026 |
| `.claude/skills/vuln-scan/` (modified) | anthropics/defending-code-reference-harness | Apache-2.0 | Anthropic PBC, 2026 |
| `.claude/skills/vuln-scan/setup-tools.sh` | net-new (this repo) | MIT | Christo Goosen, 2026 |
| `.claude/skills/triage/` | anthropics/defending-code-reference-harness | Apache-2.0 | Anthropic PBC, 2026 |
| `.claude/skills/patch/` | anthropics/defending-code-reference-harness | Apache-2.0 | Anthropic PBC, 2026 |
| `.claude/skills/security-audit/RECONNAISSANCE.md` | cloudflare/security-audit-skill | MIT | Cloudflare, Inc. 2025-2026 |
| `.claude/skills/security-audit/HUNTING.md` | cloudflare/security-audit-skill | MIT | Cloudflare, Inc. 2025-2026 |
| `.claude/skills/security-audit/ATTACK-CLASSES.md` | cloudflare/security-audit-skill | MIT | Cloudflare, Inc. 2025-2026 |
| `.claude/skills/security-audit/VALIDATION-AND-REPORTING.md` | cloudflare/security-audit-skill | MIT | Cloudflare, Inc. 2025-2026 |
| `.claude/skills/security-audit/report-schema.json` | cloudflare/security-audit-skill | MIT | Cloudflare, Inc. 2025-2026 |
| `.claude/skills/security-audit/validate-findings.cjs` | cloudflare/security-audit-skill | MIT | Cloudflare, Inc. 2025-2026 |
| `.claude/skills/security-audit/SKILL.md` | net-new (this repo) | MIT | Christo Goosen, 2026 |

## 1. Anthropic — defending-code reference harness

- **Repository:** https://github.com/anthropics/defending-code-reference-harness
- **License:** Apache License 2.0 — Copyright (c) Anthropic PBC, 2026
- **License text:** [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt)

**What is used:** the four staged security skills — `threat-model`, `vuln-scan`,
`triage`, and `patch` — vendored under `.claude/skills/`. They provide the staged
pipeline and the structured artifacts that flow between stages
(`THREAT_MODEL.md` → `VULN-FINDINGS.json` → `TRIAGE.json` → `PATCHES/`).

**Modifications** (per Apache-2.0 §4(b), changes are stated here):

- `threat-model`, `triage`, `patch` — vendored unmodified; orchestrated by the
  `security-audit` skill rather than altered.
- `vuln-scan` — **modified**. Added a deterministic pre-scan layer
  (Steps 0–0e) that wraps five external scanners — semgrep, osv-scanner, grype
  (gated on a Dockerfile), gitleaks (always-on), and checkov (gated on IaC) —
  whose results seed the existing subagent fan-out and are merged as candidate
  findings; added a `source` field and per-source/tool summary counts to the
  output; and added `setup-tools.sh` to install the scanners. These additions
  are original to this repo and offered under the MIT License (Copyright (c)
  2026 Christo Goosen); the surrounding Apache-2.0 skill retains its original
  license.

## 2. Cloudflare — security-audit skill

- **Repository:** https://github.com/cloudflare/security-audit-skill
  (path: `skills/security-audit`)
- **License:** MIT License — Copyright (c) 2025-2026 Cloudflare, Inc.
- **License text:** [`LICENSES/MIT-Cloudflare.txt`](LICENSES/MIT-Cloudflare.txt)

**What is used:** the audit *methodology* documents and helper assets —
`RECONNAISSANCE.md`, `HUNTING.md`, `ATTACK-CLASSES.md`,
`VALIDATION-AND-REPORTING.md`, `report-schema.json`, and `validate-findings.cjs`
— vendored verbatim into `.claude/skills/security-audit/`.

**Modifications:** the listed files are vendored verbatim. The MIT copyright and
permission notice are preserved via `LICENSES/MIT-Cloudflare.txt` as required by
the MIT terms.

## 3. Combined / net-new material

`.claude/skills/security-audit/SKILL.md` is original glue authored for this repo.
It sequences the Anthropic pipeline skills and applies the Cloudflare methodology
at each phase. It is offered under the MIT License (Copyright (c) 2026 Christo
Goosen). It does **not** relicense the upstream components above: each retains the
license listed in its row of the summary table.

## 4. Invoked external tools (not redistributed)

The modified `vuln-scan` skill *invokes* the following scanners at runtime. They
are not bundled or redistributed in this repo — `setup-tools.sh` installs them
from their own upstreams under their own licenses:

- **semgrep** — https://github.com/semgrep/semgrep (LGPL-2.1 CLI)
- **osv-scanner** — https://github.com/google/osv-scanner (Apache-2.0)
- **grype** — https://github.com/anchore/grype (Apache-2.0)
- **gitleaks** — https://github.com/gitleaks/gitleaks (MIT)
- **checkov** — https://github.com/bridgecrewio/checkov (Apache-2.0)

## Compliance notes

- **Apache-2.0** (Anthropic): redistribution retains the license and any NOTICE
  content; this file serves as the attribution record. Apache-2.0 material is not
  relicensed — it is combined, not converted.
- **MIT** (Cloudflare): the copyright notice and permission notice are included in
  `LICENSES/MIT-Cloudflare.txt`, satisfying the MIT redistribution condition.
