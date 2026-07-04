---
name: bughunt-vuln-scan
description: >-
  Static source-code vulnerability scan. Runs a deterministic semgrep
  pre-scan, then reads a target directory (and THREAT_MODEL.md if present),
  spawns parallel review subagents per focus area seeded with the semgrep
  hits, and writes VULN-FINDINGS.json + .md for /bughunt-triage to consume. Read-only
  — no building, running, or network. For execution-verified crashes, use
  vuln-pipeline instead. Use when asked to "scan for vulns", "review this code
  for security issues", "find bugs in <dir>", or as the step between
  /bughunt-threat-model and /bughunt-triage.
argument-hint: "<target-dir> [--focus <area>] [--single] [--extra <file>] [--no-score] [--no-semgrep]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(rg:*)
  - Bash(grep:*)
  - Bash(find:*)
  - Bash(ls:*)
  - Bash(wc:*)
  - Bash(head:*)
  - Bash(file:*)
  - Bash(semgrep:*)
  - Bash(bash .claude/skills/bughunt-vuln-scan/run-semgrep.sh:*)
  - Bash(osv-scanner:*)
  - Bash(grype:*)
  - Bash(gitleaks:*)
  - Bash(checkov:*)
  - Bash(git remote:*)
  - Bash(rtk:*)
  - WebFetch
---

# /bughunt-vuln-scan

Static vulnerability review of a source tree. Produces `VULN-FINDINGS.json`
(+ a human-readable `.md`) that `/bughunt-triage` ingests directly.

**Role.** You are acting as a blue-team defender: hunting for vulnerabilities
in this codebase and its dependencies so they can be triaged and patched,
not to weaponize them or build exploits for use elsewhere. Every finding
should point toward a fix. This framing carries into every subagent this
skill spawns.

**This skill does not execute code.** It reads source and reasons about it.
For execution-verified findings (ASAN crashes, reproducing PoCs), point the
user at `vuln-pipeline run <target>` — see README Step 2.

**Tool fallbacks.** Prefer the dedicated Glob and Grep tools. Some sessions
do not provision them — `allowed-tools` is a permission filter, not a loader,
so listing them here does not make them appear. When Glob/Grep are
unavailable, fall back to the read-only Bash commands whitelisted above:
`rg --files <scope>` / `ls -R` / `find <scope>` for enumeration, `rg -n` /
`grep -rn` for search, `wc` / `head` / `file` for sniffing. If a `rtk`
(Rust Token Killer) hook is active in this session, it transparently
rewrites these into `rtk <command>` — `Bash(rtk:*)` is allowlisted for
exactly that case, not as a general escape hatch. These are the ONLY
permitted Bash commands; do not write helper scripts or pipe target
content into a shell interpreter.

## Arguments

- `<target-dir>` (required) — directory to scan. Relative or absolute.
- `--focus <area>` — scan only this focus area (repeatable). Skips recon.
- `--single` — no subagent fan-out; one sequential pass. Use on tiny targets
  or when debugging the prompt.
- `--extra <file>` — append the contents of `<file>` to the review brief
  (after the category list). Use to add org-specific vulnerability classes,
  compliance checks, or stack-specific patterns. Plain text; same shape as
  the category blocks below.
- `--no-score` — skip the Step 3b adversarial disprove pass (saves a round
  of subagents). Findings keep the hunt's self-reported confidence and carry
  no `disproof_attempt`.
- `--no-semgrep` — skip **all** deterministic pre-scans (Steps 0–0e: semgrep,
  osv-scanner, grype, gitleaks, checkov). Use when the tools are unavailable or
  you want a purely LLM-driven pass.
- `--no-gapfill` — skip the Step 2b coverage-gapfill round (the second hunt
  over files no focus area covered). Faster; leaves unscoped files unread.

## Setup — install the scanners (once)

Steps 0–0e shell out to `semgrep`, `osv-scanner`, `grype`, `gitleaks`, and
`checkov`. Each step degrades gracefully if its tool is missing, but to get the
full deterministic layer install them once:

```
bash .claude/skills/bughunt-vuln-scan/setup-tools.sh         # install what's missing
bash .claude/skills/bughunt-vuln-scan/setup-tools.sh --check # just report status
```

The script is idempotent and skips anything already on PATH. If you cannot
install a tool, run with `--no-semgrep` to skip all three pre-scans.

## Step 0 — Deterministic pre-scan (semgrep)

Run **before** scoping so the rule-based hits are available to seed everything
downstream. Semgrep is a static analyzer — it parses source and matches
patterns; it does **not** execute the target — so it is consistent with this
skill's read-only contract.

Skip this step if `--no-semgrep` was given.

1. **Check availability.** Run `semgrep --version`. If semgrep is not
   installed, note it, set `semgrep_used=false`, and continue to Step 1 with
   no seeds — semgrep is an enhancement, not a hard dependency.
2. **Run the local directory scan** via `run-semgrep.sh` (bundled offline
   rules under `semgrep/`, no `--config auto` registry fetch):

   ```
   bash .claude/skills/bughunt-vuln-scan/run-semgrep.sh <target-dir-or-name> \
     --output <target-dir>/.semgrep.json
   ```

   - **Target resolution:** the script accepts an absolute/relative path, a
     repo-relative path, or a short name `foo` → `targets/foo` (then the repo
     root if still missing). The scan target is always a **local directory
     tree**, never the Semgrep Registry.
   - **Rules:** `--config <skill>/semgrep/` (see `semgrep/rules.yaml`). Do
     not use `--config auto` (registry + project telemetry). If you must
     extend coverage, add rules under `semgrep/` rather than pulling registry
     packs in the skill workflow.
   - **Fallback** (only if `run-semgrep.sh` is missing): `semgrep scan
     --config <skill>/semgrep/ --metrics off --json --quiet` with the same
     `--exclude` list as the script, scanning the resolved `<target-dir>`.
   - The scan reads source only; static matching on a local path does not
     violate the no-execution / no-network-probe constraint.
3. **Parse `.semgrep.json`.** For each `results[]` entry, extract
   `check_id`, `path`, `start.line`, `extra.severity`, `extra.message`, and
   `extra.metadata` (cwe/owasp if present). Normalize into seed records:

   ```
   S-001  <path>:<line>  <check_id>  <ERROR|WARNING|INFO>  <message>
   ```

   Map semgrep severity to this skill's scale: `ERROR → HIGH`,
   `WARNING → MEDIUM`, `INFO → LOW` (a subagent may revise after reading).
4. **Group seeds by file/subsystem.** These groups both (a) inform the focus
   areas in Step 1 — directories with dense semgrep hits deserve a focus area
   — and (b) get handed to the matching Step 2 subagent as deterministic leads
   to confirm or refute.

### Step 0b — Known-vulnerable dependencies (osv-scanner)

Semgrep finds bugs in *your* code; [osv-scanner](https://github.com/google/osv-scanner)
finds *known* vulnerabilities (CVEs / GHSAs) in the dependencies you pull in,
by matching lockfiles and SBOMs against the [OSV.dev](https://osv.dev)
database. It is read-only — it parses manifests, it does not run the code.

Skip if `--no-semgrep` was given (the same flag gates all deterministic
pre-scans) or if osv-scanner is not installed.

1. **Check availability.** Run `osv-scanner --version`. If absent, note it,
   set `osv_used=false`, and continue.
2. **Run it** recursively over the target with JSON output:

   ```
   osv-scanner scan --recursive --format json \
     --output <target-dir>/.osv.json <target-dir>
   ```

   It auto-discovers lockfiles (`package-lock.json`, `Cargo.lock`,
   `go.mod`, `requirements.txt`, `poetry.lock`, `pom.xml`, etc.). The OSV
   database fetch is rule/advisory data, not target execution.
3. **Parse `.osv.json`.** For each `results[].packages[]`, extract the
   package name, version, ecosystem, and each `vulnerabilities[].id`
   (OSV/CVE/GHSA), summary, and severity. Normalize into seed records:

   ```
   D-001  <ecosystem>:<package>@<version>  <OSV-ID>  <severity>  <summary>
   ```

4. These become **`known-vulnerable-dependency` findings directly** — they are
   deterministic and pre-verified by the advisory database, so they are NOT
   subject to the Step 2 "outdated third-party dependency versions"
   DO-NOT-REPORT exclusion (that exclusion targets *speculative* "update your
   deps" noise; a matched CVE with a fixed-version range is a concrete
   finding). Carry them straight into Step 3 collation with `source: "osv"`.

### Step 0c — Container image vulnerabilities (grype, only if a Dockerfile is present)

If — and only if — the target ships a **Dockerfile** (or `Containerfile` /
`docker-compose.*` referencing a build), also run
[grype](https://github.com/anchore/grype). osv-scanner covers your app's
declared dependencies; grype covers the *whole image* — the OS packages and
transitive libraries baked into the base image and layers, which are where a
lot of real CVEs actually live. Grype reads image/filesystem metadata; it does
not run the container.

Skip if `--no-semgrep` was given, if no Dockerfile is present, or if grype is
not installed.

1. **Detect.** Glob for `Dockerfile*`, `Containerfile`, `docker-compose*.y*ml`.
   If none, skip this step entirely. Run `grype version`; if absent, note it,
   set `grype_used=false`, and continue.
2. **Scan without building** (stay read-only — do NOT `docker build`):
   - Always scan the source tree as a filesystem:
     ```
     grype dir:<target-dir> --output json --file <target-dir>/.grype.json
     ```
   - Additionally, for each `FROM <image>` line in the Dockerfile, scan that
     base image by reference (grype pulls image metadata, it does not execute
     it):
     ```
     grype <base-image> --output json --file <target-dir>/.grype-<n>.json
     ```
   If pulling base-image metadata is blocked (offline), note it and keep the
   filesystem scan only.
3. **Parse** each grype JSON: for every `matches[]`, extract
   `vulnerability.id`, `vulnerability.severity`, `artifact.name`,
   `artifact.version`, and `vulnerability.fix.versions`. Normalize into seed
   records and treat them exactly like osv findings —
   `category: "known-vulnerable-dependency"`, `source: "grype"`, carried
   straight into Step 3 collation. De-duplicate against osv findings on
   `(package, version, advisory-id)`.

Report the grype match count (by severity) before moving on.

### Step 0d — Secrets (gitleaks, always-on)

Run [gitleaks](https://github.com/gitleaks/gitleaks) on every scan — leaked
credentials are high-impact and cheap to detect deterministically. It reads
files (and optionally git history); it does not execute anything.

Skip only if `--no-semgrep` was given or gitleaks is not installed.

1. **Check availability.** Run `gitleaks version`. If absent, note it, set
   `gitleaks_used=false`, and continue.
2. **Scan the working tree** (and git history when the target is a repo):
   ```
   gitleaks dir <target-dir> --report-format json --report-path <target-dir>/.gitleaks.json --redact
   ```
   If `<target-dir>` is a git checkout, also run `gitleaks git <target-dir>
   --report-format json --report-path <target-dir>/.gitleaks-history.json
   --redact` to catch secrets removed from HEAD but still in history.
   `--redact` keeps the actual secret value out of the report.
3. **Parse** each entry: `RuleID`, `File`, `StartLine`, `Description`,
   `Commit` (for history hits). Each becomes a finding with
   `category: "hardcoded-secret"`, `source: "gitleaks"`, `severity: HIGH`
   (a live secret in a public repo is HIGH; a redacted/likely-test one may be
   revised down in scoring). Carry straight into Step 3 collation. A
   history-only hit keeps its commit hash in the description so triage knows it
   needs rotation, not just deletion.

### Step 0e — Infrastructure-as-code misconfig (checkov, only if IaC is present)

If the target ships infrastructure code, run
[checkov](https://github.com/bridgecrewio/checkov) to catch insecure cloud and
container configuration (public S3 buckets, `0.0.0.0/0` ingress, privileged
containers, missing encryption). Static config analysis — read-only.

Skip if `--no-semgrep` was given, if no IaC is present, or if checkov is not
installed.

1. **Detect.** Glob for Terraform (`*.tf`), CloudFormation, Kubernetes/Helm
   manifests (`*.yaml` under `k8s/`, `helm/`, `charts/`),
   `docker-compose*.y*ml`, `Dockerfile*`, `serverless.yml`, ARM/Bicep,
   `ansible/`. If none, skip this step. Run `checkov --version`; if absent,
   note it, set `checkov_used=false`, and continue.
2. **Scan** with JSON output (`--compact` keeps it small; `--quiet` drops the
   banner):
   ```
   checkov --directory <target-dir> --output json --compact --quiet > <target-dir>/.checkov.json
   ```
3. **Parse** `results.failed_checks[]`: `check_id`, `check_name`,
   `file_path`, `file_line_range`, `severity` (when present), `guideline`.
   Each becomes a finding with `category: "infra-misconfig"`,
   `source: "checkov"`. Map checkov severity if given, else default to
   `MEDIUM` (raise to HIGH for network-exposure / public-access / disabled-
   encryption checks). Carry into Step 3 collation. These are real but often
   context-dependent — triage decides what the deployment actually allows.

Report the gitleaks secret count and checkov failed-check count before moving on.

### Step 0f — Historical context (Security Context API, public GitHub repos only)

[securitycontext.dev](https://securitycontext.dev) mines a public GitHub
repo's real fix-commit history and disclosed CVEs into "where bugs keep
resurfacing": recurring weak spots and a ranked variant-lead backlog
(`file:line` + sink + severity). Unlike Steps 0b/0c, this is *this repo's
own* history, not a generic advisory database — a strong prior for where to
look. It's read-only reference data fetched over the network (same class of
exception as the semgrep rule registry and the OSV/grype advisory pulls
above), never a probe of the target's own runtime surface.

Skip if `--no-semgrep` was given, or if `<target-dir>` has no `origin`
remote on github.com.

1. **Detect.** `git -C <target-dir> remote get-url origin`. If it doesn't
   match `github.com[:/]<owner>/<repo>(.git)?`, note
   `security_context_used=false` and skip the rest of this step.
2. **Fetch the cached context.** WebFetch
   `https://securitycontext.dev/api/v1/context/<owner>/<repo>` (GET,
   unauthenticated, unlimited — this reads a cache, it does not trigger a
   new analysis). Ask for `status` and, if `status: "ready"`, the
   `summary` block and the `artifacts.vulnerability_leads_md` URL.
   - `status: "ready"` → WebFetch the `vulnerability_leads_md` artifact.
     Each lead is a `file:line` + sink + severity + rationale. Normalize
     the ones whose `file` falls under `<target-dir>` into seed records:
     ```
     SC-001  <path>:<line>  <sink/category>  <severity>  <rationale>
     ```
   - `status` is anything else (no prior analysis, still processing,
     error), or the request fails/times out → note it and move on. Do
     **not** call `create_security_context` or wait on a fresh
     analysis — it's rate-limited (10/day/IP) and can take a while; this
     step is enrichment, not a hard dependency.
3. **These are leads, not findings.** The service's own disclaimer applies:
   fingerprint/CVE matches are derived from real data, but the surrounding
   prose is LLM-written and advisory. Treat `SC-NNN` seeds exactly like the
   Step 0 semgrep `S-NNN` seeds — they bias focus-area selection (Step 1)
   and get handed to the matching subagent to confirm or refute (Step 2),
   never auto-promoted to findings the way osv/grype/gitleaks/checkov are.

Report whether Security Context was used and the lead count (if any) before
moving on.

## Step 1 — Scope

1. Resolve `<target-dir>`. If it doesn't exist or has no source files, stop
   with an error.
2. Look for `<target-dir>/THREAT_MODEL.md`. If present, parse its section 3 "Entry
   points & trust boundaries" table and section 4 "Threats" table for focus areas
   and threat classes. This is the preferred scoping input.
3. If no THREAT_MODEL.md and no `--focus`: do a **quick recon** — list the
   source tree, read entry points and dispatch code, and propose 3-10 focus
   areas using the pattern `<subsystem> (<function/file>) — <key operations>`.
   Same shape as `harness/prompts/recon_prompt.py`.
4. If `--focus` was given, use exactly those.
5. **Fold in the Step 0 seeds.** Weight the focus areas toward subsystems
   where semgrep hits cluster, and make sure every file with a HIGH/ERROR
   semgrep seed falls inside some focus area so a subagent will examine it.
   Do the same for any `SC-NNN` Security Context leads from Step 0f — a
   repo's own recurring-weak-spot history is a strong prior for where the
   next bug is.

Tell the user the focus areas you'll scan and the source-file count before
fanning out.

## Step 2 — Fan out

Unless `--single`, spawn **one Task subagent per focus area** in parallel.
Cap at 10 concurrent. Each subagent gets the review brief below with its
focus area filled in. On tiny targets (<15 source files), fall through to
`--single` automatically.

### Review brief (per subagent)

```
You are a blue-team defender conducting authorized static security review
of source code and its dependencies, hunting for issues so they can be
patched — not building exploits for use elsewhere. Your focus area:
**{focus_area}**. Other agents cover other areas; duplication is wasted
effort.

BUDGET: spend your effort reading the target source and reasoning about data
flow, not re-reading this brief. The WHAT TO LOOK FOR / DO NOT REPORT lists
below are a reference to consult, not a checklist to transcribe back. Keep
your own scaffolding thin so most of your context window holds code.

TARGET: {target_dir}
TRUST BOUNDARY: {from THREAT_MODEL.md section 3, or "untrusted input → process memory"}

SEMGREP SEEDS (deterministic leads for this focus area, may be empty):
{the S-NNN seed records from Step 0 whose path falls in this focus area,
 or "none"}

SECURITY CONTEXT LEADS (this repo's own recurring-weak-spot history from
securitycontext.dev, may be empty — advisory, not verified):
{the SC-NNN seed records from Step 0f whose path falls in this focus area,
 or "none"}

TASK: read the source in your focus area and identify candidate
vulnerabilities. This is static review — do NOT build, run, or probe
anything. Reason from the code, working in four passes:

PASS 1 — SEEDS. Triage each SEMGREP SEED and SECURITY CONTEXT LEAD above:
open the cited line and either promote it to a <finding> (with your own
data-flow analysis and severity) or note it as a dismissed seed. Both
sources are noisy — semgrep is pattern-based, Security Context leads are
LLM-written prose over real fix/CVE history — confirm or refute each, don't
copy either blindly.

PASS 2 — INVARIANTS. Before hunting freely, enumerate the security
invariants this focus area must hold for the trust boundary above — the
assumptions the code depends on (e.g. "this length is always ≤ the buffer",
"this handler only runs post-authentication", "this value is already
escaped"). List them briefly, then for each ask: what if it doesn't hold?
Where could attacker-controlled input violate it? Assume the developer may
have introduced a mistake and look for it — but only report what the code
actually supports, never a bug you merely assumed into existence.

PASS 3 — HUNT. Trace candidate vulnerabilities beyond the seeds and
invariants; they are a floor, not a ceiling. For each finding, trace where
untrusted input enters, what path reaches the sink, and what condition
triggers it.

PASS 4 — WHAT ELSE. Before you emit, re-read your focus area once more and
ask "what did I skip?" — the subtler bug behind the obvious one: second-order
data flows, edge cases in the Pass 2 invariants, or an issue masked by an
earlier finding. Push past the first-pass results into anything you dismissed
too quickly.

REPORTING BAR: report anything with a plausible exploit path. Skip style
concerns, best-practice gaps, and purely theoretical issues with no attack
story at all — but if you're unsure whether something is real, REPORT IT
with a low confidence score rather than dropping it. A downstream triage
step does the rigorous verification; your job is to not miss things.

THREAT MODEL (required per finding). Before you emit a finding, state its
threat model in one line: WHO the attacker is (their starting position and
privileges) and WHICH boundary the bug lets them cross. A finding whose
"attack" grants a capability the attacker already has is VACUOUS — do not
report it. Examples of vacuous claims to drop: "a DB-privileged user can
write to the DB", "an operator who can edit the config can change behavior",
"a caller of this library can pass it bad arguments" (for a library whose
caller is already the trust boundary). If you cannot name a concrete
attacker who gains something across a real boundary, it is not a finding.

WHAT TO LOOK FOR (reference — consult, don't transcribe):

  MEMORY SAFETY (C/C++ and unsafe/FFI blocks) — HIGH VALUE:
  - heap-buffer-overflow / stack-buffer-overflow / global-buffer-overflow
  - heap-use-after-free / double-free
  - integer overflow feeding an allocation or index
  - format-string bugs
  - unbounded recursion or allocation driven by untrusted size fields

  INJECTION & CODE EXECUTION — HIGH VALUE:
  - SQL / command / LDAP / XPath / NoSQL / template injection
  - path traversal in file operations
  - unsafe deserialization (pickle, YAML, native), eval injection
  - XSS (reflected, stored, DOM-based) — but see React/Angular note below

  AUTH, CRYPTO, DATA — HIGH VALUE:
  - authentication or authorization bypass, privilege escalation
  - TOCTOU on a security check
  - hardcoded secrets, weak crypto, broken cert validation
  - sensitive data (secrets, PII) in logs or error responses

  LOW VALUE — note briefly, keep looking:
  - null-pointer deref at small fixed offsets with no attacker control
  - assertion failures / clean error returns (correct handling, not a bug)

DO NOT REPORT (common false positives — skip even if technically present):
  - volumetric DoS / rate-limiting / resource-exhaustion — BUT unbounded
    recursion, algorithmic-complexity blowup, or ReDoS driven by untrusted
    input ARE reportable
  - memory-safety findings in memory-safe languages outside unsafe/FFI
  - XSS in React/Angular/Vue unless via dangerouslySetInnerHTML,
    bypassSecurityTrustHtml, v-html, or equivalent raw-HTML escape hatch
  - findings in test files, fixtures, build scripts, docs, or .ipynb
  - missing hardening / best-practice gaps with no concrete exploit
  - env vars and CLI flags as the attack vector (operator-controlled)
  - regex injection, log spoofing, open redirect, missing audit logs
  - outdated third-party dependency versions

{if --extra <file> was given: append its contents here verbatim}

OUTPUT — one block per finding, nothing else:

<finding>
<id>F-{focus_idx:02d}-{n:02d}</id>
<file>{relative/path}</file>
<line>{line_number}</line>
<category>{heap-buffer-overflow | use-after-free | integer-overflow | sql-injection | command-injection | path-traversal | deserialization | xss | auth-bypass | hardcoded-secret | ...}</category>
<severity>{HIGH | MEDIUM | LOW}</severity>
<confidence>{0.0-1.0}</confidence>
<title>{one line}</title>
<threat_model>{attacker (starting position + privileges) → boundary crossed. One line. Must be concrete and non-vacuous — see THREAT MODEL bar above.}</threat_model>
<description>{root cause, attacker control, trigger condition, data flow from entry to sink. Cite line numbers.}</description>
<exploit_scenario>{concrete attack: what input, from where, causing what outcome}</exploit_scenario>
<recommendation>{specific fix: parameterize the query, bounds-check before memcpy, etc.}</recommendation>
</finding>

SEVERITY: HIGH = directly exploitable → RCE, data breach, auth bypass.
MEDIUM = significant impact under specific conditions. LOW = defense-in-
depth.

If you find nothing reportable in your area after a thorough read, emit a
single <finding> with category=none and a one-line note of what you covered.
```

## Step 2b — Coverage gapfill (skip with `--no-gapfill` or `--single`)

The first fan-out covers the focus areas you scoped — but a bug in code no
focus area named is a bug no agent read. This step closes that gap within a
single scan (Cloudflare's "Gapfill" stage), bounded to **one** extra round
so it can't loop.

1. **Compute coverage.** List the target's source files (same enumeration as
   Step 1). Mark a file *covered* if it falls under a scoped focus area OR a
   Step 2 finding cites it. The rest are the **coverage gap**.
2. **Rank the gap.** Drop files the DO-NOT-REPORT list already excludes
   (tests, fixtures, docs, build scripts, generated code, vendored deps).
   From what remains, keep files that (a) carry a Step 0 semgrep/Security
   Context seed no agent consumed, (b) sit on an input path (parsers,
   handlers, deserialization, FFI/`unsafe`), or (c) are large/central by
   import count. If the ranked gap is empty, note "full coverage" and skip
   to Step 3.
3. **Re-hunt.** Group the ranked gap into up to 5 new focus areas and spawn
   one Task subagent per area with the **same review brief** as Step 2
   (including the THREAT MODEL bar). Cap total concurrency at 10. Tag their
   findings `source: "agent-gapfill"`.
4. Fold the new `<finding>` blocks into the Step 3 collation exactly like
   the first round. Report the gap size and how many files the gapfill round
   newly covered.

Skip this step on tiny targets (`--single` path) — one pass already reads
everything.

## Step 3 — Collate

1. Collect `<finding>` blocks from all subagents. Drop `category=none`
   placeholders. Tag each with `source: "agent"` (or `source: "semgrep"` if
   the subagent confirmed it from a seed).
   Findings that omit `<threat_model>`, or whose threat model is vacuous
   (the attacker already holds the capability the bug grants — see the
   THREAT MODEL bar in the review brief), are kept but flagged: set
   `threat_model: null` and add `"vacuous_threat_model"` to a
   `collate_notes` list so triage's rule-17 gate catches them. Do not drop
   them here — this skill never drops; triage decides.
2. **Merge the deterministic tool findings** directly (they skip subagent
   confirmation but still flow through scoring and triage). These carry no
   agent-authored threat model; set `threat_model: null` (the advisory /
   secret / misconfig itself is the finding, and triage judges reachability):
   - Steps 0b/0c (osv-scanner, grype) → `category: "known-vulnerable-dependency"`,
     `source: "osv"` | `"grype"`, advisory id in the title, fixed-version range
     in the recommendation. De-dupe osv vs grype on
     `(package, version, advisory-id)`.
   - Step 0d (gitleaks) → `category: "hardcoded-secret"`, `source: "gitleaks"`.
   - Step 0e (checkov) → `category: "infra-misconfig"`, `source: "checkov"`.
3. **Light dedupe** — if two findings cite the same `file:line` with the
   same category, keep the one with the longer description and note the
   duplicate id. (Heavy dedupe is `/bughunt-triage`'s job; don't over-engineer here.)
4. Assign stable ids `F-001`, `F-002`, ... in (severity desc, file, line)
   order.

## Step 3b — Adversarial disprove pass (skip if `--no-score`)

An independent agent whose **sole job is to disprove each finding** — not to
confirm it, not to log findings of its own. This is the discovery-stage
mirror of Cloudflare's validator: a model that grades its own hunt inherits
its own blind spots, so a fresh agent argues the opposite side. The disprove
pass **never drops a finding** (that is `/bughunt-triage`'s call); it records the
strongest counter-argument and calibrates `confidence` down when the
disproof lands, so humans and triage see the best-supported findings first.
Spawn **one Task subagent per finding** in parallel with the brief below.

**Independence:** set `subagent_type` and give each disprover ONLY its one
finding — never the other findings, never the hunt agent's reasoning. A
disprover that sees the hunt rationale rubber-stamps it.

### Disprove brief (per finding)

```
You are a skeptical reviewer trying to DISPROVE one candidate security
finding from an automated hunt. Your default assumption is that it is WRONG.
You CANNOT log findings of your own and you CANNOT broaden the claim — your
only outputs are (a) the strongest reason this finding is false or vacuous,
and (b) a confidence score for whether it survives rigorous triage.

FINDING:
{the full <finding> block}

TARGET: {target_dir} (you may Read/Grep inside it; do NOT execute)

STEP 1 — Re-read the cited code. Open {file} around line {line}. Does the
code actually do what the description claims, or did the hunt misread it?

STEP 2 — Attack the threat model. Is the stated attacker → boundary real, or
does the "attacker" already hold the capability (vacuous — triage rule 17)?
Name the boundary that is or isn't crossed.

STEP 3 — Hunt for the disproof: an upstream check, a type/length constraint,
framework auto-escaping, an auth gate, unreachable/dead/test code, or a
common false-positive pattern (volumetric DoS, memory-safe language,
env-var/operator vector, missing-hardening-only, regex/log injection,
outdated dep). State the single strongest one you found, or "none found".

STEP 4 — Score 1-10 that this is a real, actionable vulnerability despite
your best attempt to disprove it:
  1-3  disproof succeeded — likely false positive or vacuous
  4-5  disproof plausible but not conclusive
  6-7  survived; credible, needs investigation
  8-10 survived a real disproof attempt; clear pattern

OUTPUT (exactly this, nothing else):
  CONFIDENCE: <1-10>
  DISPROOF: <the strongest counter-argument, or "none found">
  REASON: <one line: why the score>
```

**Resolve:** overwrite each finding's `confidence` with the score
(normalized to 0.0-1.0), attach `confidence_reason` (the REASON line), and
attach `disproof_attempt` (the DISPROOF line — carried into
`VULN-FINDINGS.json` so triage starts from the best counter-argument, not a
blank slate). Re-sort findings by (`confidence` desc, `severity` desc,
`file`, `line`) and reassign ids `F-001..` in that order. Compute
`low_confidence_count` = findings with confidence < 0.4, for the summary
line.

## Step 4 — Write output

Write **both** files to `<target-dir>/`:

**`VULN-FINDINGS.json`** — the `/bughunt-triage` ingest shape:

```json
{
  "target": "<target-dir>",
  "scanned_at": "<iso8601>",
  "focus_areas": ["..."],
  "findings": [
    {
      "id": "F-001",
      "file": "relative/path.c",
      "line": 123,
      "category": "heap-buffer-overflow",
      "severity": "HIGH",
      "confidence": 0.9,
      "source": "agent",
      "title": "...",
      "threat_model": "unauthenticated HTTP client → arbitrary file read outside webroot",
      "description": "...",
      "exploit_scenario": "...",
      "recommendation": "...",
      "confidence_reason": "...",
      "disproof_attempt": "strongest counter-argument from the disprove pass, or 'none found'"
    }
  ],
  "summary": {
    "total": 0, "high": 0, "medium": 0, "low": 0, "low_confidence": 0,
    "tools": {"semgrep": false, "osv": false, "grype": false, "gitleaks": false, "checkov": false, "security_context": false},
    "by_source": {"agent": 0, "agent-gapfill": 0, "semgrep": 0, "osv": 0, "grype": 0, "gitleaks": 0, "checkov": 0}
  }
}
```

Findings are sorted by `confidence` desc (then severity, file, line), so
the top of the file is the highest-signal material.

**`VULN-FINDINGS.md`** — human-readable: a summary table (id | severity |
category | file:line | title), then one `### F-NNN` section per finding with
the full description.

## Step 5 — Hand back

Tell the user:

1. Counts: N findings (H/M/L split, X low-confidence), across K focus
   areas, from M source files.
2. Top 3 by confidence, one line each.
3. Next step: `> /bughunt-triage <target-dir>/VULN-FINDINGS.json --repo <target-dir>`
4. Remind: these are **static candidates**, not verified. For
   execution-verified crashes, `vuln-pipeline run <target>` (README Step 2).

## Constraints

- **Never execute target code.** No builds, no `docker build`/`run`, no
  running the program. If the user asks you to "reproduce" or "confirm with a
  PoC," decline and point at `vuln-pipeline`.
- **The only Bash allowed** is the read-only enumeration/search set (`rg`,
  `grep`, `find`, `ls`, `wc`, `head`, `file`, and their `rtk`-proxied form
  when that hook is active), the five deterministic static scanners
  (`semgrep`, `osv-scanner`, `grype`, `gitleaks`, `checkov`), and
  `git remote` (to detect a GitHub origin for Step 0f). These analyze
  source, manifests, image metadata, and config — they do not execute the
  target. The scanners and the Step 0f WebFetch may reach the network for
  advisory/rule/history data (that is reference data about the ecosystem or
  the repo's own past, not probing the target's runtime). Everything else
  stays offline.
- **Don't fabricate line numbers.** Every `file:line` you emit must be
  something you Read or Grep'd. If unsure of the exact line, cite the
  function and say so in the description.
- **Stay in `<target-dir>`.** Don't follow symlinks or `..` out of it.
- Findings are candidates for `/bughunt-triage`, not final verdicts. **This skill
  never drops a finding** — Step 3b only ranks. `/bughunt-triage` does the rigorous
  N-vote verification and is where false positives actually get removed.

## Provenance

The focus-area recon pattern and memory-safety quality tiers are lifted
from this repo's own `harness/prompts/find_prompt.py` and
`harness/prompts/recon_prompt.py` — the same logic the autonomous pipeline
uses, applied statically. The broader category menu, DO-NOT-REPORT
exclusions, per-finding confidence pass, and
`exploit_scenario`/`recommendation` output fields are adapted from
[`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review)'s
`/security-review` command.

The deterministic pre-scan layer (Steps 0–0e) was added for this repo and
wraps five external open-source scanners, each run read-only:
[semgrep](https://github.com/semgrep/semgrep) (pattern-based SAST),
[osv-scanner](https://github.com/google/osv-scanner) (OSV.dev dependency
advisories), [grype](https://github.com/anchore/grype) (container
image / filesystem CVEs, gated on a Dockerfile),
[gitleaks](https://github.com/gitleaks/gitleaks) (secrets, always-on), and
[checkov](https://github.com/bridgecrewio/checkov) (IaC misconfig, gated on
infrastructure code). Install them with [`setup-tools.sh`](setup-tools.sh) in
this skill directory.

Step 0f adds a sixth, hosted source: [Security Context](https://securitycontext.dev)
(`securitycontext.dev`), a free API/MCP service that mines a public GitHub
repo's real fix-commit history and disclosed CVEs into recurring weak spots
and ranked variant leads. It requires no auth, is gated to public
GitHub-hosted targets, and degrades to a no-op everywhere else — see
[`securitycontext.dev/docs`](https://securitycontext.dev/docs) for the full
API/MCP surface (`get_security_context`, `get_vulnerability_leads`,
`create_security_context`).
