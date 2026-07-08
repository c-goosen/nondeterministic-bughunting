## Provenance

The focus-area recon pattern and memory-safety quality tiers are lifted
from this repo's own `harness/prompts/find_prompt.py` and
`harness/prompts/recon_prompt.py` — the same logic the autonomous pipeline
uses, applied statically. The broader category menu, DO-NOT-REPORT
exclusions, per-finding confidence pass, and
`exploit_scenario`/`recommendation` output fields are adapted from
[`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review)'s
`/security-review` command.

The deterministic pre-scan layer (Steps 0–0e and 0g) was added for this repo
and wraps six external open-source scanners, each run read-only:
[semgrep](https://github.com/semgrep/semgrep) (pattern-based SAST),
[osv-scanner](https://github.com/google/osv-scanner) (OSV.dev dependency
advisories), [grype](https://github.com/anchore/grype) (container
image / filesystem CVEs, gated on a Dockerfile),
[gitleaks](https://github.com/gitleaks/gitleaks) (secrets, always-on),
[checkov](https://github.com/bridgecrewio/checkov) (IaC misconfig, gated on
infrastructure code), and
[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) (Go
callgraph-reachable dependency CVEs, gated on a `go.mod`). Install them with
[`setup-tools.sh`](setup-tools.sh) in this skill directory.

Step 0f adds a hosted source: [Security Context](https://securitycontext.dev)
(`securitycontext.dev`), a free API/MCP service that mines a public GitHub
repo's real fix-commit history and disclosed CVEs into recurring weak spots
and ranked variant leads. It requires no auth, is gated to public
GitHub-hosted targets, and degrades to a no-op everywhere else — see
[`securitycontext.dev/docs`](https://securitycontext.dev/docs) for the full
API/MCP surface (`get_security_context`, `get_vulnerability_leads`,
`create_security_context`).
