---
name: bughunt-triage
description: Triage a batch of raw security findings. Verify each is real,
  collapse duplicates, re-rank by derived exploitability, and tag with an
  owner. Phase 3 uses a multi-model verifier panel (one model per vote) and
  a judge on the largest capable model available for split votes. Takes a
  directory or file of scanner output and writes TRIAGE.json + TRIAGE.md
  sorted by what actually needs engineering attention. Use when asked to
  "triage findings", "validate scanner output", "prioritize vulns", or
  "review the backlog". Runs interactively by default; pass --auto to skip
  the interview.
argument-hint: "<findings-path> [--auto] [--votes N] [--repo PATH] [--fp-rules FILE] [--fresh] [--judge-model SLUG]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - AskUserQuestion
  - Bash(git log:*)
  - Bash(git remote:*)
  - Bash(jq:*)
  - Bash(find:*)
  - Bash(ls:*)
  - Bash(wc:*)
  - Bash(python3 .claude/skills/_lib/checkpoint.py:*)
  - WebFetch
---

# bughunt-triage

Adversarial triage of raw security-scanner output. Does four jobs:
**verify** each finding is real, **deduplicate** across runs and scanners,
**rank** survivors by derived exploitability rather than the scanner's
claimed severity, and **route** each to a component owner. Output is a
short, ranked, owned list instead of a raw dump.

Invoke with `/bughunt-triage <findings-path> [--auto] [--votes N] [--repo PATH] [--fp-rules FILE] [--judge-model SLUG]`.

**Arguments** (parse from `$ARGUMENTS`; positional `$1`/`$2` expansion is
not stable across runtimes):
- findings path (first positional, required): a JSON file, a directory of
  JSON files, a `VULN-FINDINGS.json`, a pipeline `results/<target>/<ts>/`
  directory, or a markdown report.
- `--auto`: skip the interview and use defaults. Default mode is
  **interactive**.
- `--votes N`: verifier votes per finding (default 3; use 1 for a quick
  pass, 5 for high-stakes batches). Each vote is spawned on a **different
  model** from the verifier panel (Phase 3b) to reduce single-model blind
  spots.
- `--repo PATH`: path to the target codebase, read-only (default cwd).
  Verification needs source access; the skill stops with an error if the
  cited files aren't reachable.
- `--fp-rules FILE`: append the contents of FILE to the verifier's
  exclusion-rule list (Phase 3a). Use for org-specific precedents: "we use
  Prisma ORM everywhere — raw-query SQLi only", "k8s resource limits cover
  DoS", etc. Plain text, one rule per line or paragraph.
- `--judge-model SLUG`: optional override for the Phase 3d judge `model`
  parameter on Task calls. When omitted, pick the **largest / most capable
  model available** from the platform allowlist (see Phase 0e).
- `--fresh`: ignore any existing checkpoint in `./.triage-state/` and start
  from Phase 0. Without this flag the skill resumes from the last completed
  phase if a checkpoint is present.

**Tools:** Read, Glob, Grep, Write, Task, AskUserQuestion. Bash is
permitted only for `git`, `find`, `wc`, `ls`, `jq`, and
`python3 .claude/skills/_lib/checkpoint.py` (checkpoint I/O).

**Do not execute target code.** No building, running, installing
dependencies, or sending requests. A proof-of-concept that accidentally
works against something real is unacceptable, and "couldn't write a working
PoC" is weak evidence of non-exploitability. Every conclusion comes from
reading source. This applies to the orchestrator and every subagent;
include the constraint in every Task prompt. For high-confidence HIGH
findings, recommend a human-built PoC as a follow-up instead.

**Do not reach the network**, with one narrow exception: Phase 0d may fetch
the cached [Security Context](https://securitycontext.dev) brief for
`--repo`, a single read of a third-party history/advisory cache scoped to
the repo under review — never a package-registry lookup, a live CVE-database
query, or any probe of the target's own runtime surface. No other network
access is permitted anywhere in this skill, including inside subagents.

---

## Checkpointing (runs before Phase 0 and after every phase)

On large finding batches a full run can exhaust context or hit rate limits
mid-way — particularly Phase 3, which spawns `candidates × votes` verifiers.
Phase state persists to `./.triage-state/` so a fresh `/bughunt-triage` session can
resume without re-asking the interview or re-spawning verifiers.

All checkpoint I/O goes through `python3 .claude/skills/_lib/checkpoint.py`
(atomic writes, JSON-validated). Never use the Write tool for `progress.json`
directly. Never pass payload via heredoc or stdin; target-derived strings
could collide with the heredoc delimiter and break out to shell. The
Write→`--from` pattern keeps repo-derived bytes out of Bash argv.

State files in `./.triage-state/`:
- `progress.json` — **single source of truth** for resume position:
  `{"status": "running"|"complete", "phase_done": N, "shards_done": [...]}`.
  Resume decisions read ONLY this file, never a glob of `phase*.json` or
  shard files (stale files from a prior run must not be trusted).
- `phaseN.json` — data payload for phase N (schemas at the tail of each phase
  section below). `phase0.json` is the sole writer of `context`; phases 1–5
  checkpoints omit it — checkpoint.py's merge reconstructs full working state
  from `phase0.json` + `phaseN.json` in sequence.
- `_chunk.tmp` — transient payload buffer; overwritten before every
  `save`/`shard`/`append` call.

**Start of run — resume check.** Bash:
`python3 .claude/skills/_lib/checkpoint.py load ./.triage-state`

- `status == "absent"` OR `"complete"`, OR `--fresh` in `$ARGUMENTS` →
  **fresh start.** Bash:
  `python3 .claude/skills/_lib/checkpoint.py reset ./.triage-state`,
  then proceed to Phase 0.
- `status == "running"` with `phase_done == N` → **resume.** Read
  `./.triage-state/phase0.json` through `phaseN.json` **in order** (and any
  `shard_*.json` files listed in `shards_done`), merging keys into working
  state (later files override earlier — checkpoints may be deltas). Print
  `Resuming from checkpoint: Phase N complete (./.triage-state/phaseN.json)`,
  and **skip directly to Phase N+1**.

**End of every phase N.** Two tool calls:
1. Write tool → `./.triage-state/_chunk.tmp` containing the phase's output
   JSON (schema at the tail of each phase section).
2. Bash → `python3 .claude/skills/_lib/checkpoint.py save ./.triage-state <N> <name> --from ./.triage-state/_chunk.tmp`

**End of run.** After writing `TRIAGE.json` and `TRIAGE.md`, Bash:
`python3 .claude/skills/_lib/checkpoint.py done ./.triage-state 6`

---

## Phase 0: Mode select and interview

### 0a. Parse arguments

From `$ARGUMENTS`: extract the findings path (first positional), `--auto`
flag, `--votes N` (default 3), `--repo PATH` (default `.`), `--fp-rules
FILE` (default none), `--judge-model SLUG` (default none). If no findings
path was given, ask for one and stop. If `--fp-rules` was given, Read the
file now and carry its contents as `context.extra_fp_rules` for injection
into the Phase 3a verifier prompt.

### 0b. Interactive mode (default): interview the user

Unless `--auto` was passed, use **AskUserQuestion** to gather context that
shapes verification and ranking. Batch into one or two calls of up to four
questions. Expect free-text answers via "Other"; the multiple-choice options
are prompts, not constraints.

**Round 1** (single AskUserQuestion call):

1. **Environment & trust boundary** (header `Environment`, single-select)
   `What kind of system are these findings from, and where does untrusted
   input enter it?`
   Options: `Internet-facing web service (HTTP is untrusted)`,
   `Internal service (callers are authenticated peers)`,
   `Library / SDK (caller is the trust boundary)`,
   `CLI / batch tool (operator inputs trusted, file inputs not)`,
   `Embedded / firmware (physical access in scope)`.
   Reachability is judged against this boundary; "command injection from env
   var" is a true positive in a multi-tenant web service and a rule-8 false
   positive in an operator CLI.

2. **Threat model** (header `Threat model`, multi-select)
   `What does a worst-case attacker look like for this system, and what
   must never happen? Free text is best.`
   Options: `Unauthenticated remote code execution`,
   `Tenant-to-tenant data leakage`, `Privilege escalation to admin`,
   `Supply-chain compromise of downstream users`,
   `Denial of service against a paid SLA`,
   `Compliance-scoped data exposure (PII / PCI / PHI)`.
   Phase 4 boosts findings that map onto a stated threat.

3. **Scoring standard** (header `Scoring`, single-select)
   `How should severity be expressed in the output?`
   Options: `Derived HIGH/MEDIUM/LOW from preconditions (default)`,
   `CVSS v3.1 vector + base score`, `CVSS v4.0 vector + base score`,
   `OWASP Risk Rating (likelihood x impact)`,
   `Organization bug-bar (describe in Other)`.
   The precondition rule is always computed; this controls what
   `severity_label` additionally shows.

4. **Noise tolerance** (header `Noise tolerance`, single-select)
   `When verifiers disagree, which way should ties break?`
   Options:
   `Precision: drop anything not majority-confirmed (fewer FPs, may miss real bugs)`,
   `Recall: keep split votes as needs_manual_test (more to review, fewer misses)`,
   `Ask me per-finding when it happens`.

**Round 2** (conditional): if the threat-model answer was empty or generic,
or the scoring answer was `Organization bug-bar`, ask one targeted follow-up.

Record the answers as a `context` dict carried through every phase and
echoed in the output under `triage_context`.

### 0c. Auto mode defaults

When `--auto` is set, do not call AskUserQuestion. Use:
- Environment: `Unknown. Treat any externally-reachable entry point as
  untrusted; flag trust-boundary assumptions explicitly in rationale.`
- Threat model: empty (no boost).
- Scoring: derived HIGH/MEDIUM/LOW.
- Noise tolerance: precision.

### 0d. Optional: Security Context enrichment (public GitHub repos only)

Best-effort, non-blocking. If it fails or doesn't apply, proceed with
`context.security_context = null` — nothing downstream depends on it.

1. Bash: `git -C {REPO} remote get-url origin`. If it doesn't match
   `github.com[:/]<owner>/<repo>(.git)?`, skip.
2. WebFetch `https://securitycontext.dev/api/v1/context/<owner>/<repo>`
   (GET, unauthenticated — reads a cache, never triggers a new analysis).
   On `status: "ready"`, also WebFetch the `artifacts.security_context_md`
   URL for the prose summary of recurring weak spots and known CVEs. On any
   other status or a failed/timed-out request, skip.
3. Set `context.security_context = {cves, fixes, recurring_weak_spots: [...]}`
   (counts and a short list of named weak spots/subsystems), or `null`.

**This never feeds Phase 3 verification.** Verifiers must stay code-only
and adversarial; telling a verifier "this file has a history of bugs" would
bias it toward TRUE_POSITIVE on a claim it should be trying to disprove. It
is only consumed by Phase 4 ranking (4a) as a capped threat-match signal,
and echoed in the TRIAGE.md header for reviewer context.

### 0e. Multi-model panel and judge selection

Phase 3 uses a **diverse verifier panel** (one model per vote) and a
**judge model** (largest / most capable available) to break split votes.
Record both in `context` before verification starts.

**Platform allowlist** (Cursor `Task` tool `model` parameter — update if the
runtime's list changes; never pass a slug not on the list):

| Tier | Model slug | Role |
|------|------------|------|
| 1 | `claude-opus-4-8-thinking-high` | Judge (preferred) |
| 1 | `claude-sonnet-5-thinking-high` | Judge fallback / verifier |
| 1 | `claude-fable-5-thinking-high` | Judge fallback / verifier |
| 1 | `gpt-5.3-codex` | Judge fallback / verifier |
| 2 | `claude-4.6-sonnet-medium-thinking` | Verifier panel |
| 2 | `gpt-5.5-medium` | Verifier panel |
| 2 | `composer-2.5-fast` | Verifier panel (cheap sweep) |

**Judge model (`context.judge_model`):**
- If `--judge-model SLUG` was passed, use it (must be on the allowlist).
- Else walk the Tier-1 list top-to-bottom and set `context.judge_model` to
  the **first** slug you can use on Task calls. Prefer the largest /
  highest-thinking model available (`claude-opus-4-8-thinking-high` first).
- The judge is used only in Phase 3d (split / tie / majority
  `CANNOT_VERIFY`). It is the binding verdict on those findings.

**Verifier panel (`context.verifier_models`):** ordered list of slugs for
round-robin assignment across votes. Build it as:
1. Start with Tier-2 slugs in an order that **alternates model families**
   (Anthropic ↔ OpenAI ↔ Composer), e.g.
   `claude-4.6-sonnet-medium-thinking`, `gpt-5.5-medium`,
   `composer-2.5-fast`.
2. Append any Tier-1 slugs not chosen as judge (deduped).
3. If the list is shorter than `--votes`, cycle it; if longer, truncate to
   `votes` unique assignments per finding by round-robin.

Every verifier Task in Phase 3b **must** set `model:` to
`context.verifier_models[(k-1) % len(verifier_models)]` for vote `k`.
Every judge Task in Phase 3d **must** set `model: context.judge_model`.

**Checkpoint:** Write tool → `./.triage-state/_chunk.tmp`:

```json
{"phase": 0, "context": {mode, environment, threat_model, scoring, noise_tolerance, votes_per_finding, repo, findings_path, security_context, judge_model, verifier_models}}
```

Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.triage-state 0 interview --from ./.triage-state/_chunk.tmp`
On resume past Phase 0, the interview is **not** re-asked; `context` is
restored from this file.

---

## Phase 1: Ingest and normalize

Turn the input into a flat `findings[]` list with stable ids, regardless of
source format.

### 1a. Detect input shape

Inspect the findings path:

- **Directory**: Glob for `**/*.json` and `**/*.jsonl`. Recognized
  containers, in priority order:
  - `VULN-FINDINGS.json` (a `{findings: [...]}` container): read
    `.findings[]`.
  - `reports/bug_*/report.json` or `reports/manifest.jsonl` (this repo's
    pipeline output): one finding per `bug_NN`. Map `crash.crash_type` →
    `category`, `verdict.severity_rating` → `severity`, the prose `report` →
    `description`, crash file from the ASAN top frame → `file`/`line`.
  - `found_bugs.jsonl`: one finding per line.
  - Any other `*.json` whose top level is a list of objects, or an object
    with a `findings`/`results`/`issues`/`vulnerabilities` array: that
    array.
- **Single `.json` / `.jsonl` file**: same recognition as above.
- **Markdown / text**: split on level-2/3 headings or `---` rules; for each
  section, extract `file`, `line`, `category`, `severity`, `description` by
  pattern (`File:`, `Line:`, `Severity:` labels or `path:NN` spans).
  Best-effort; mark `source_format: "markdown_heuristic"`.

If nothing parseable is found, stop and report what was seen.

### 1b. Normalize fields

For each raw record, build a finding dict. **Pull what's present; never
guess what's absent.** Field map (source-key aliases → canonical):

| Canonical       | Also accept                                              |
|-----------------|----------------------------------------------------------|
| `file`          | `path`, `location.file`, `filename`, ASAN top-frame file |
| `line`          | `line_number`, `location.line`, `lineno`                 |
| `category`      | `type`, `cwe`, `rule_id`, `crash_type`, `vulnerability_class` |
| `severity`      | `severity_rating`, `level`, `priority`, `risk`           |
| `title`         | `name`, `summary`, `message`                             |
| `description`   | `details`, `report`, `body`, `evidence`                  |
| `exploit_scenario` | `attack_scenario`, `poc`, `reproduction`              |
| `threat_model`  | `threat`, `attacker_model`, `attacker`                    |
| `disproof_attempt` | `disproof`, `counter_argument`                        |
| `preconditions` | `requirements`, `assumptions`                            |
| `recommendation`| `fix`, `remediation`, `mitigation`                       |
| `scanner_confidence` | `confidence`, `score`, `certainty` (normalize to 0.0-1.0) |

Attach to every finding:
- `id`: `f001`, `f002`, ... in ingest order. If `scanner_confidence` is
  present on most findings, order ingest by it descending so high-signal
  findings get verified (and surface in partial output) first; otherwise
  keep source order. This is a scheduling prior only — it does not affect
  verdicts.
- `source`: relative path of the file it came from, plus source format.
- `missing_fields`: list of canonical fields that were absent. If `file` is
  missing or does not resolve under `--repo`, the finding is
  **unlocatable**: it skips dedup and verification and is emitted directly
  with `verdict: false_positive`, `verify_verdict: needs_manual_test`,
  `confidence: 0`, `refute_reasons: ["doesnt_exist"]`, `rationale: "no
  source location in input; cannot verify statically; human review
  required"`. Never emit a confident verdict on a finding you could not
  locate, and never let it absorb or be absorbed by dedup.

### 1c. Locate the target codebase

Resolve `--repo` (default cwd). For the first 5 findings with a `file`,
check the path resolves under the repo. Try, in order: (a) `repo/file`
as-given; (b) `file` as an absolute or cwd-relative path; (c) `repo/file`
with common prefixes stripped from `file` (`src/`, `app/`, `./`, or the
repo's own basename, e.g. `harness/grade.py` with `--repo harness`).
Record which resolution worked and apply it to every finding. If none
resolve, **stop**: tell the user verification needs source access and the
cited files aren't reachable, and suggest a `--repo` value based on the
longest common suffix you can see.

**Checkpoint:** Write tool → `./.triage-state/_chunk.tmp`:

```json
{"phase": 1, "findings": [ {normalized finding dicts with id/source/file/line/category/...} ], "path_resolution": "<which of a/b/c worked>"}
```

Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.triage-state 1 ingest --from ./.triage-state/_chunk.tmp`

---

## Phase 2: Deduplicate (before verification)

Collapse repeats so duplicate findings don't each burn N verifiers.

### 2a. Deterministic pass (inline, no subagent)

Cluster findings where all of:
- same `file` (after path normalization), AND
- same `category` (case-insensitive, punctuation stripped), AND
- `line` numbers within 10 of each other. Both-missing matches; one-side-
  missing does NOT (a line-less record must not absorb a located one).

Within each cluster, the canonical is the record with the fewest
`missing_fields`; ties break to lowest `id`. Every other member gets
`verdict: duplicate`, `duplicate_of: <canonical id>`, and is removed from
the working set. Record duplicate ids on the canonical as `absorbed: [...]`.

### 2b. Semantic pass (one subagent, only if >1 cluster survives)

Spawn ONE Task with `subagent_type: "general-purpose"` and this prompt:

```
You are deduplicating security findings before expensive verification. Two
findings are DUPLICATES if fixing one would also fix the other. Two findings
are DISTINCT if they have genuinely independent root causes, even if they
share a category or file.

Treat as DUPLICATE:
- Same root cause described with different wording or by different scanners
- A shared vulnerable helper function reported once per call site
- A missing global protection (auth check, output encoding) reported once
  per endpoint that lacks it
- A cause ("missing input validation on `name`") and its consequence
  ("SQL injection via `name`") in the same code path

Treat as DISTINCT:
- Different categories in the same file region (an "ssrf" near a
  "buffer_overflow" is not a duplicate just because the lines are close)
- Same file, same category, but different tainted variables reaching
  different sinks
- Same helper, but two independent bugs inside it
- Two endpoints missing the same check, where the fix is per-endpoint
  rather than a shared gate

Below are the candidate findings (one per line: id | file:line | category |
title). Group them. Respond with ONLY lines of the form:

  GROUP: <canonical_id> <- <dup_id>, <dup_id>, ...

One line per group that has duplicates. Omit singletons. Pick the most
specific / best-described finding as canonical. No prose.

CANDIDATES:
{one line per surviving finding: "f003 | src/auth.py:112 | sql_injection | User lookup concatenates name into query"}
```

Parse `GROUP:` lines. For each, mark the listed dup ids with
`verdict: duplicate`, `duplicate_of: <canonical>`, append them to the
canonical's `absorbed`, and drop them from the working set.

Carry forward `candidates[]` = the surviving canonicals.

**Checkpoint:** Write tool → `./.triage-state/_chunk.tmp`:

```json
{"phase": 2, "findings": [ {all findings; duplicates carry verdict/duplicate_of} ], "candidates": ["f001", "f003", "..."]}
```

Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.triage-state 2 dedup --from ./.triage-state/_chunk.tmp`

---

## Phase 3: Verify

For each candidate, N independent adversarial verifiers re-derive the claim
from the code and vote — **each on a different model** from
`context.verifier_models` (Phase 0e). Split outcomes go to a **judge** on
`context.judge_model` (the largest / most capable model available).
Each verifier's stance is "find any reason this is wrong." Each starts from
the code at the cited location, not the scanner's description, and never sees
the other verifiers' reasoning (shared context propagates blind spots).
The judge may see all N verdict blocks but must still re-read the cited
source and issue its own binding decision.

### 3a. Exclusion rules (canonical source for verifiers and judge)

The compact verifier form in §3b is used for all Phase 3b spawns; this
section is the canonical rule list the compact form abbreviates and the
Phase 3d judge references as "same 1-17."

EXCLUSION RULES: if the finding matches any of these, it is FALSE_POSITIVE
even if technically accurate. Cite the rule number in your verdict.

  1. Volumetric DoS or missing rate-limiting (handled at infrastructure
     layer). ReDoS, algorithmic complexity, and unbounded recursion ARE
     still valid findings.
  2. Test-only code, dead code, example/fixture code, or a crash with no
     security impact.
  3. Behavior that is the intended design (compression middleware, a
     backward-compatible weak algorithm offered alongside a strong one).
  4. Memory-safety concerns in memory-safe languages outside `unsafe` /
     FFI blocks.
  5. SSRF where the attacker controls only the path, not the host or
     protocol.
  6. User input flowing into an AI/LLM prompt (prompt injection is not a
     code vulnerability in the target).
  7. Path traversal in object storage (S3/GCS) where `../` does not escape
     a trust boundary.
  8. Trusted inputs used as the attack vector (env vars, CLI flags set by
     the operator), UNLESS the ENVIRONMENT above marks them untrusted.
  9. Client-side code flagged for server-side vulnerability classes.
 10. Outdated dependency versions (managed by a separate process).
 11. Weak random used for non-security purposes (jitter, shuffling,
     dev-only fallbacks).
 12. Low-impact nuisance issues (log spoofing, CSRF on logout, self-XSS,
     tabnabbing, open redirect, regex injection).
 13. Missing hardening or best-practice gap with no concrete exploit path
     (missing security headers, no audit logging, permissive config that
     isn't actually reached by untrusted input).
 14. XSS in a framework with default auto-escaping (React, Angular, Vue,
     Jinja2 autoescape=on) UNLESS the sink is a raw-HTML escape hatch
     (dangerouslySetInnerHTML, bypassSecurityTrustHtml, v-html, |safe).
 15. Identifiers that are unguessable by construction (UUIDv4, 128-bit+
     random tokens) flagged as "predictable" or "needs validation".
 16. Race conditions or TOCTOU that are theoretical only — no realistic
     window, or no security-relevant state changes between check and use.
 17. Vacuous threat model: the "attacker" already holds the capability the
     bug supposedly grants, so no trust boundary is actually crossed
     (a DB-privileged user writing to the DB; an operator who edits config
     changing behavior; a library caller — when the caller IS the trust
     boundary per ENVIRONMENT — passing malicious arguments). Judge this
     against the ENVIRONMENT above: the same primitive can be rule-17 in a
     CLI/library and a real finding in a multi-tenant web service. If the
     finding carries a `threat_model` field, verify it names a concrete
     attacker crossing a real boundary; if it is null, vacuous, or
     contradicted by the code, this rule applies.

{if context.extra_fp_rules: append here verbatim under an
 "ORG-SPECIFIC RULES:" heading}

### 3b. Spawn N verifiers per candidate, all in one message

For each finding in `candidates[]`, build N Task calls (N = `--votes`,
default 3) with `subagent_type: "general-purpose"`, `description:
"verify {id} vote {k}/{N}"`, and **`model:` set to the k-th panel slot**:

```
model = context.verifier_models[(k - 1) % len(context.verifier_models)]
```

**Always set `subagent_type` and `model`; never fork.** Omitting
`subagent_type` forks the orchestrator, and a fork inherits the full
conversation context: every other finding's description, the scanner's
prose, and any prior verifier results. That defeats verifier independence
and re-introduces the inherited-framing failure mode this phase exists to
prevent. Each verifier must start with a fresh, empty context and receive
only the 3a prompt plus the single finding under review. The same applies
to the ranking subagents in 4a and the judge in 3d (judge gets verdict
blocks only, not other findings).

Each prompt is the verifier prompt from 3a with this block appended:

```
────────────────────────────────────────────────────────────────────────
FINDING UNDER REVIEW (from the scanner; treat as a CLAIM, not a fact):

  id:        {id}
  file:      {file}
  line:      {line}
  category:  {category}
  severity (claimed): {severity}
  title:     {title}

  threat_model (claimed attacker → boundary; may be null):
  {threat_model or "(not provided — check rule 17)"}

  description:
  {description}

  exploit_scenario:
  {exploit_scenario or "(not provided)"}

  prior disproof attempt (from the scan's disprove pass; a counter-argument
  to weigh, NOT a verdict to defer to):
  {disproof_attempt or "(none)"}

  preconditions (claimed):
  {preconditions as bullets or "(not provided)"}

You are vote {k} of {N} on model {model_slug}. You have NOT seen the other
verifiers' reasoning and you must NOT try to find it. Work independently
from the code.
```

**Put all verifier Task calls in a single assistant message** so they run
concurrently. Do not set `run_in_background`; you need the final text, not
an async handle. If `len(candidates) * N` exceeds ~40, shard into
sequential batches of ~40, but keep each batch a single message.

**Prompt size.** Use the compact form below by default for **all** Phase 3b
verifier spawns — same procedure, same exclusion rules, same output contract,
~80% fewer tokens. Reserve the full 3a prompt for the Phase 3d judge only:
split-vote cases benefit from the extra procedure prose; routine verifiers do not.

```
Adversarially verify ONE scanner finding. Default: scanner is WRONG.
Read-only access scoped to {REPO_PATH} ONLY. No exec, no network.
ENVIRONMENT: {context.environment}

Steps: (1) Read {file}:{line} yourself; don't trust the description.
(2) Trace callers backwards; quote the first call-site file:line.
(3) Hunt for protections: validation, escaping, type bounds, auth gates,
dead/test code. (4) Stress-test each protection on every path.

Exclusion rules (FALSE_POSITIVE if matched): 1 volumetric DoS;
2 test/dead/fixture code; 3 intended design; 4 memory-safety in safe
lang outside unsafe/FFI; 5 SSRF path-only; 6 LLM prompt input;
7 object-storage traversal; 8 trusted operator env/CLI inputs;
9 client code, server vuln class; 10 outdated deps; 11 weak random
non-security; 12 low-impact nuisance (log spoof, open redirect, regex
inject); 13 missing-hardening-only, no concrete exploit; 14 XSS in
auto-escape framework w/o raw-HTML escape hatch; 15 unguessable
UUID/token flagged predictable; 16 theoretical-only race/TOCTOU;
17 vacuous threat model (attacker already holds the capability; no boundary
crossed — judge against ENVIRONMENT; applies if threat_model is null/vacuous).
{+ org rules from --fp-rules if any}

End with EXACTLY:
  VERDICT: TRUE_POSITIVE | FALSE_POSITIVE | CANNOT_VERIFY
  CONFIDENCE: <0-10>
  REFUTE_REASON: <doesnt_exist|already_handled|implausible_trigger|
    intentional_behavior|misread_code|duplicate|not_actionable|n/a>
  EXCLUSION_RULE: <1-17, org rule, or none>
  FIRST_LINK: <file:line or "none found">
  RATIONALE: <2-5 sentences, file:line cited>

FINDING: {id} {file}:{line} {category} (claimed {severity})
{title}
{description}
Vote {k}/{N} on {model_slug}. Independent; do not seek other votes.
```

Findings with a `file` but no `line` get **one** verifier vote regardless
of `--votes` (a file-level sweep is expensive and doesn't benefit from
voting).

**If any Task call returns `status: "async_launched"`**, follow the recovery
procedure in `.claude/skills/_lib/async-recovery.md`. The same recovery
applies to the dedupe subagent in 2b and the ranking subagents in 4a.

### 3c. Tally votes

For each candidate, parse the trailing block from each of its N verifiers
(tolerate code fences and whitespace). Record each vote's `model` slug in
`vote_models: [{vote: k, model: slug, verdict: ...}, ...]`. If a verifier
errored, timed out, or produced no parseable VERDICT block, re-spawn it once
on the **same** panel model. If the retry also fails, count that vote as
`cannot_verify` with `confidence: 0` and note `"verifier_error"` in
`refute_reasons`. The remaining N-1 votes still decide.

Build:

- `vote_breakdown`: `{"true_positive": x, "false_positive": y,
  "cannot_verify": z}`
- `confidence`: mean CONFIDENCE across votes that agree with the majority,
  rounded to one decimal (before judge; updated after judge in 3d).
- `exclusion_rule`: the modal EXCLUSION_RULE among FALSE_POSITIVE votes,
  else `null`.
- `refute_reasons`: sorted unique REFUTE_REASON values from FALSE_POSITIVE
  votes.
- `first_links`: unique FIRST_LINK values across all votes (reachability
  audit trail).
- `rationale`: the RATIONALE from the highest-confidence vote on the
  winning side, verbatim (replaced by judge rationale when 3d runs).

**Provisional `verdict` (before judge):**
- Unanimous TRUE_POSITIVE (all N) → `verdict: true_positive`. Skip 3d.
- Unanimous FALSE_POSITIVE (all N) → `verdict: false_positive`. Skip 3d.
- Clear majority TRUE_POSITIVE or FALSE_POSITIVE (strictly more than half
  of N, and majority is not CANNOT_VERIFY) → use that side. Skip 3d.
- **Otherwise** (tie, split, or majority CANNOT_VERIFY) → proceed to **3d
  judge**. Do not apply noise_tolerance yet.

### 3d. Judge split votes (largest capable model)

When 3c did not produce a clear majority, spawn **one** Task with
`subagent_type: "general-purpose"`, `model: context.judge_model`, and
`description: "judge {id}"`. The judge prompt:

```
You are the BINDING judge for a split security-finding verification. N
independent verifiers on different models reviewed the same scanner claim;
they did not reach a clear majority. Your job is to read the source code
yourself and issue the final TRUE_POSITIVE or FALSE_POSITIVE verdict.

You have read-only access to the target codebase at: {REPO_PATH}
You may use Read, Glob, and Grep only inside {REPO_PATH}. No build, run,
install, or network.

ENVIRONMENT: {context.environment}

PROCEDURE:
1. Read {file}:{line} yourself — do not trust the scanner or the panel.
2. Trace reachability from untrusted input per ENVIRONMENT.
3. Hunt for and stress-test protections (same exclusion rules as verifiers).
4. Review the panel's verdict blocks below for disagreements to investigate,
   not to rubber-stamp. You may adopt a panel argument only if you verify
   it against source.

EXCLUSION RULES: same 1-17 (+ org rules) as Phase 3a verifiers.

PANEL VOTES (models and verdict blocks only):
{for each vote k:}
  --- Vote {k} ({model_slug}) ---
  VERDICT: ...
  CONFIDENCE: ...
  REFUTE_REASON: ...
  EXCLUSION_RULE: ...
  FIRST_LINK: ...
  RATIONALE: ...

FINDING UNDER REVIEW:
  id: {id}
  file: {file}:{line}
  category: {category}
  title: {title}
  description: {description}
  exploit_scenario: {exploit_scenario or "(not provided)"}

Respond with ONLY this block (binding):

  VERDICT: TRUE_POSITIVE | FALSE_POSITIVE
  CONFIDENCE: <0-10>
  REFUTE_REASON: <doesnt_exist|already_handled|implausible_trigger|
    intentional_behavior|misread_code|duplicate|not_actionable|n/a>
  EXCLUSION_RULE: <1-17, org rule, or none>
  FIRST_LINK: <file:line or "none found">
  RATIONALE: <2-5 sentences citing file:line; note which panel disagreements
    you confirmed or rejected>
  JUDGE_MODEL: {context.judge_model}
```

Parse the judge block and **override** the provisional tally:
- `verdict`: judge TRUE_POSITIVE → `true_positive`; FALSE_POSITIVE →
  `false_positive`.
- `confidence`: judge CONFIDENCE.
- `rationale`: judge RATIONALE (prefix with `[judge:{judge_model}] `).
- `judge_invoked: true`, `judge_model: context.judge_model`.
- Merge judge FIRST_LINK into `first_links`.

If the judge Task errors, fall back to noise_tolerance policy from 3c
(without judge):
  - `precision` → `false_positive` + `"(split vote, judge failed, precision policy)"`
  - `recall` → `true_positive`, `verify_verdict: needs_manual_test`
  - `ask` → AskUserQuestion at end of Phase 3

When 3c produced a clear majority and 3d was skipped: `judge_invoked: false`,
`judge_model: null`.

Build `confirmed[]` = candidates with final `verdict == true_positive`.

**Checkpoint:** Write tool → `./.triage-state/_chunk.tmp`:

```json
{"phase": 3, "findings": [ {all findings with verdict/vote_breakdown/vote_models/confidence/refute_reasons/first_links/rationale/exclusion_rule/judge_invoked/judge_model} ], "confirmed": ["f001", "..."]}
```

Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.triage-state 3 verify --from ./.triage-state/_chunk.tmp`

This is the most expensive checkpoint. When `len(candidates) * votes` exceeds
~40 and verifier spawns are sharded into sequential batches, additionally
checkpoint **per candidate** as its votes are tallied:

1. Write tool → `./.triage-state/_chunk.tmp` = that finding's post-tally dict.
2. Bash:
   `python3 .claude/skills/_lib/checkpoint.py shard ./.triage-state <id> --from ./.triage-state/_chunk.tmp`

On resume at `phase_done == 2`, the Phase-3 entry point reads
`progress.json:shards_done` (default `[]` — do **not** glob shard files on
disk; stale shards from a prior run may exist), loads the corresponding
`shard_{id}.json` files, and spawns verifiers only for `candidates[]` ids
from `phase2.json` that are NOT in `shards_done`. Once every candidate is in
`shards_done`, write the consolidated `phase3.json` checkpoint as above.

---

## Phase 4: Rank by exploitability (confirmed findings only)

Recompute severity from preconditions and reachability rather than category
name, and judge the scanner's claimed severity separately. Verification and
severity are independent judgments; "this is real" must not inflate into
"this is critical."

### 4a. Ranking prompt

When `context.threat_model` is empty and `context.security_context` is null,
omit the THREAT MODEL and HISTORICAL CONTEXT stanzas from the prompt —
STEP 3 of the ranking procedure becomes unreachable and the stanza labels
still burn tokens.

Spawn one Task per confirmed finding (`subagent_type: "general-purpose"`,
all in one message) with:

```
You are assigning severity to a CONFIRMED security finding. Verification
already happened; assume the finding is real. Your only job is to derive
how bad it is, independently of what the scanner claimed.

You may Read/Grep the codebase at {REPO_PATH} to check preconditions. Do
NOT execute code.

ENVIRONMENT: {context.environment}
{if context.threat_model non-empty:}
THREAT MODEL (operator-stated):
{context.threat_model as bullets}
{/if}
{if context.security_context non-null:}
HISTORICAL CONTEXT (this repo's own fix/CVE history via securitycontext.dev):
{context.security_context.recurring_weak_spots as bullets}
{/if}
SCORING STANDARD: {context.scoring}

FINDING:
  id:        {id}
  file:      {file}:{line}
  category:  {category}
  claimed severity: {severity}
  reachability evidence: {first_links from Phase 3}
  verifier rationale: {rationale from Phase 3}

────────────────────────────────────────────────────────────────────────
STEP 1: Enumerate EVERY precondition that must hold for exploitation.
Be concrete: required auth state, configuration, prior request, race
window, attacker position. Then state the minimum ACCESS LEVEL required
(unauthenticated remote / authenticated / local / physical).

STEP 2: Derive severity from the precondition count and access level:

  | Preconditions | Access required          | Severity |
  |---------------|--------------------------|----------|
  | 0             | Unauthenticated remote   | HIGH     |
  | 1-2           | Authenticated            | MEDIUM   |
  | 3+            | Local-only / no demo path| LOW      |

  Evaluate each column independently and take the LOWER result. Example:
  0 preconditions but authenticated-only is MEDIUM, not HIGH; 1
  precondition but local-only is LOW. Cross-check: if your preconditions
  list has 3+ items, HIGH is almost certainly wrong.

STEP 3: Threat-model / historical-context match. If the THREAT MODEL or the
HISTORICAL CONTEXT is non-empty and this finding maps onto an entry in
either, note which one. A match may raise severity by ONE step total (LOW
to MEDIUM or MEDIUM to HIGH), never two — even if both sources match, the
cap is one step combined, not one step each. If both are empty, skip this
step.

STEP 4: Judge the scanner's claimed severity. From the perspective of an
engineer who has reviewed two hundred scanner findings this week and is
allergic to inflation: would the CLAIMED severity contribute to alert
fatigue? Is it comparable to a real CVE at that level? Is the code in test
fixtures or dev-only config? Score in -5..+5:
  +3..+5  claimed severity is justified or understated
   0..+2  roughly right
  -1..-3  inflated by one level
  -4..-5  badly inflated (LOW dressed as HIGH)

STEP 5: verify_verdict. Exactly one of:
  exploitable        preconditions are realistically satisfiable
  mitigated          real, but a deployed control reduces it below the
                     derived severity (name the control)
  needs_manual_test  severity hinges on something only a runtime test can
                     settle; recommend a human build a PoC

STEP 6: If SCORING STANDARD is a CVSS or OWASP variant, emit a
`severity_label` in that format (vector string + base score for CVSS;
likelihood x impact for OWASP). Otherwise set it equal to the derived
HIGH/MEDIUM/LOW.

────────────────────────────────────────────────────────────────────────
Respond with ONLY this block:

  PRECONDITIONS:
  - <one per line>
  ACCESS_LEVEL: <unauthenticated_remote|authenticated|local|physical>
  SEVERITY: <HIGH|MEDIUM|LOW>
  SEVERITY_LABEL: <per scoring standard>
  THREAT_MATCH: <matched threat-model entry, or none>
  SEVERITY_ALIGNMENT: <-5..+5>
  VERIFY_VERDICT: <exploitable|mitigated|needs_manual_test>
  RANK_RATIONALE: <2-4 sentences>
```

### 4b. Merge

For each confirmed finding, parse the block and attach `preconditions`
(replacing any scanner-supplied list), `access_level`, `severity`
(recomputed), `severity_label`, `threat_match`, `severity_alignment`,
`verify_verdict`, and append RANK_RATIONALE to `rationale` (separated by a
blank line from the Phase-3 rationale).

For findings that did NOT reach Phase 4 (`false_positive`, `duplicate`,
unlocatable): set `severity: null`, `verify_verdict: null`,
`severity_alignment: null`, `preconditions: []`.

**Checkpoint:** Write tool → `./.triage-state/_chunk.tmp`:

```json
{"phase": 4, "findings": [ {all findings with severity/severity_label/preconditions/access_level/threat_match/severity_alignment/verify_verdict} ]}
```

Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.triage-state 4 rank --from ./.triage-state/_chunk.tmp`

---

## Phase 5: Route

Tag each confirmed true-positive with the most specific component or owner
inferable. For each finding in `confirmed[]`, stop at the first hit:

1. **CODEOWNERS / OWNERS.** Grep `--repo` for `CODEOWNERS`, `OWNERS`,
   `.github/CODEOWNERS`, `docs/CODEOWNERS`. If found, match the finding's
   `file` against its patterns (last match wins). Hint:
   `"CODEOWNERS: <pattern> -> <owner(s)>"`.
2. **git log.** If `--repo` is a git checkout, run
   `git -C {REPO} log --format='%an' -n 50 -- "{file}" | sort | uniq -c | sort -rn | head -3`.
   Hint: `"top committer: <name> (<n>/<total> recent commits); no
   CODEOWNERS entry"`.
3. **Module fallback.** Hint: `"component: <top-level dir of file>/; no
   CODEOWNERS or git history"`.

Attach as `owner_hint`. State the source so confidence is clear; a bare
username is less useful than `"component: auth/; no CODEOWNERS entry; top
committer jsmith (14/20 recent commits)"`. For non-true-positive findings,
set `owner_hint: null`.

**Checkpoint:** Write tool → `./.triage-state/_chunk.tmp`:

```json
{"phase": 5, "findings": [ {all findings with owner_hint} ]}
```

Then Bash:
`python3 .claude/skills/_lib/checkpoint.py save ./.triage-state 5 route --from ./.triage-state/_chunk.tmp`

---

## Phase 6: Output

### 6a. Sort

Order all findings by:
1. `verdict`: `true_positive`, then `duplicate`, then `false_positive`.
2. Within true positives: `severity` HIGH > MEDIUM > LOW, then `confidence`
   descending, then `severity_alignment` descending.
3. Within others: original `id`.

### 6b. Write `./TRIAGE.json`

```json
{
  "triage_completed": true,
  "triage_context": {
    "mode": "interactive|auto",
    "environment": "...",
    "threat_model": ["..."],
    "security_context": {"cves": 0, "fixes": 0, "recurring_weak_spots": ["..."]},
    "scoring": "...",
    "noise_tolerance": "...",
    "votes_per_finding": 3,
    "judge_model": "claude-opus-4-8-thinking-high",
    "verifier_models": ["claude-4.6-sonnet-medium-thinking", "gpt-5.5-medium", "composer-2.5-fast"],
    "repo": "..."
  },
  "summary": {
    "input_count": 0,
    "duplicates": 0,
    "false_positives": 0,
    "true_positives": 0,
    "needs_manual_test": 0,
    "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
  },
  "findings": [
    {
      "id": "f001",
      "source": "VULN-FINDINGS.json#0",
      "title": "...",
      "file": "...",
      "line": 0,
      "category": "...",
      "threat_model": "attacker → boundary, or null",
      "claimed_severity": "HIGH",
      "verdict": "true_positive|false_positive|duplicate",
      "verify_verdict": "exploitable|mitigated|needs_manual_test|null",
      "confidence": 0.0,
      "severity": "HIGH|MEDIUM|LOW|null",
      "severity_label": "...",
      "severity_alignment": 0,
      "preconditions": ["..."],
      "access_level": "...",
      "threat_match": "...|null",
      "rationale": "file:line-cited prose: reachability, protections, why each held or didn't; then ranking rationale",
      "vote_breakdown": {"true_positive": 0, "false_positive": 0, "cannot_verify": 0},
      "vote_models": [{"vote": 1, "model": "...", "verdict": "..."}],
      "judge_invoked": false,
      "judge_model": null,
      "refute_reasons": ["..."],
      "exclusion_rule": null,
      "first_links": ["file:line", "..."],
      "duplicate_of": null,
      "absorbed": ["..."],
      "owner_hint": "...",
      "missing_fields": ["..."]
    }
  ]
}
```

Every input finding appears exactly once (duplicates reference their
canonical via `duplicate_of`). Do not silently drop anything. Do not print
this JSON to the terminal; write to file only.

### 6c. Write `./TRIAGE.md`

Reviewer-facing report. Build it **incrementally**. Do NOT emit the whole
file in one Write. One chunk per finding; a stalled chunk loses that one
section, not the file.

**Step 1 — header.** Write tool → `./TRIAGE.md` (clobbers any prior file)
containing only the title block, summary, and `## Act on these` heading:

```
# Triage Report

{summary line: N in -> D duplicates, F false positives, T confirmed (H high / M med / L low), X need manual test}

Context: {mode}; environment = {environment}; scoring = {scoring};
{votes}-vote multi-model verification (panel: {verifier_models joined});
judge: {judge_model} on split votes.

## Act on these
```

**Step 2 — per finding.** For each true_positive in severity order:
1. Write tool → `./.triage-state/_chunk.tmp` containing ONE finding's section:

```
### [{severity}] {title}  ({id})
`{file}:{line}` | {category} | claimed {claimed_severity} (alignment {severity_alignment:+d}) | confidence {confidence}/10
**Owner:** {owner_hint}
**Verdict:** {verify_verdict}, votes {vote_breakdown}{if judge_invoked:} (judge: {judge_model}){/if}
**Preconditions ({n}):** {bulleted}
**Threat-model match:** {threat_match or "none"}
**Why:** {rationale}
**Reachability evidence:** {first_links}
{if verify_verdict == needs_manual_test:}
> Recommend a human build a PoC; static reasoning hit its limit.
```

2. Bash:
   `python3 .claude/skills/_lib/checkpoint.py append ./TRIAGE.md --from ./.triage-state/_chunk.tmp`

Repeat for each true_positive.

**Step 3 — footer.** Write tool → `./.triage-state/_chunk.tmp` containing the
Dropped table, then `checkpoint.py append` it the same way:

```
## Dropped

| id | title | file:line | why dropped |
{false_positives: refute_reasons + exclusion_rule}
{duplicates: "duplicate of {duplicate_of}"}
{unlocatable: "no source location in input"}
```

**Checkpoint (final):** Bash:
`python3 .claude/skills/_lib/checkpoint.py done ./.triage-state 6`
The next invocation's resume check sees `status == "complete"` and starts
fresh.

### 6d. Terminal summary

Under ~12 lines:

```
Triage complete: {N} findings -> {T} confirmed, {F} false positives, {D} duplicates.

  HIGH:   {n}   {title of top HIGH, owner_hint}
  MEDIUM: {n}
  LOW:    {n}
  Needs manual test: {n}

  Top refute reasons: {top 3 refute_reasons with counts}

Wrote ./TRIAGE.md and ./TRIAGE.json
```

See `DESIGN.md` in this skill directory for design rationale and smoke tests.
