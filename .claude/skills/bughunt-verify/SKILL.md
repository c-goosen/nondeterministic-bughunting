---
name: bughunt-verify
description: >-
  Execution-verify triaged security findings by writing a proof-of-concept
  as a test that runs against the UNTOUCHED codebase in a sandbox, then
  observing whether the vulnerability actually triggers. Consumes TRIAGE.json
  (preferred) or findings.json; promotes each finding to execution_verified,
  not_reproduced, or inconclusive, and optionally re-runs the PoC against a
  candidate patch to confirm the fix closes it. Writes VERIFY.json + VERIFY.md
  and per-finding PoCs under VERIFY/bug_NN/. This is the ONE bughunt skill that
  runs target code — always sandboxed, network-denied, authorized targets only.
  Use when asked to "verify the findings", "write PoCs and run them", "prove
  these bugs are real", or as the step between triage and report.
argument-hint: "<findings-path> [--repo PATH] [--only IDS] [--with-patch DIR] [--jobs N] [--no-sandbox] [--timeout S]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Edit
  - Task
  - Bash
---

<!--
  bughunt-verify — net-new for nondeterministic-bughunting, MIT-licensed
  (copyright 2026 Christo Goosen; see /LICENSES/MIT-Cloudflare.txt for the MIT
  text). It applies the execution-verification methodology from Cloudflare's
  "Build your own vulnerability harness" post
  (https://blog.cloudflare.com/build-your-own-vulnerability-harness/): every
  finding must ship a PoC written as a test that runs against the original,
  untouched codebase, executed in an unshare-based sandbox, with the finding
  promoted only on an observed success signal. See /NOTICES.md.
-->

# bughunt-verify

The rest of the pipeline is **read-only** — `bughunt-vuln-scan` and
`bughunt-triage` reason about source and never run it, on purpose. This skill
is the deliberate exception: it takes findings triage already believes are
real and **proves them by execution**. A finding is only `execution_verified`
here if a proof-of-concept, written as a test **against the untouched
codebase**, produces an observable success signal when run in a sandbox.

Two rules make the result trustworthy, both straight from the Cloudflare
harness methodology:

1. **The PoC runs against the original, untouched source.** The agent may not
   edit the target to manufacture a crash. This skill enforces it mechanically
   (the target copy is mounted read-only; the PoC lives outside the source
   tree), not just by instruction — "I made it crash" is worthless if the
   agent also changed the code.
2. **The observable signal decides the verdict, not the exit code.** A
   sanitizer can print `heap-buffer-overflow` and still exit 0 under a test
   wrapper; a server can return `200 OK` whose *body* is a stack trace.
   Classify the captured output, never trust the status alone.

## Authorization (read before running)

This skill **executes code**. Only run it against a target you are authorized
to test — a local checkout you control, a CTF/lab instance, or a codebase
under an active engagement. Do **not** point it at a third party's production
system, and never let a PoC reach the network (the sandbox denies it; keep it
that way). SSRF / exfil PoCs must target a canary you own, exactly as in
`bughunt-exploit-payloads`. If you cannot establish authorization, stop and
say so.

Everything runs in `run-sandboxed.sh` (this directory): no network, a
read-only view of the target, a writable scratch dir, CPU/memory/file-size
limits, and a hard timeout. If no sandbox mechanism is available, the skill
refuses to execute unless `--no-sandbox` is explicitly passed (strongly
discouraged; see Step 0c).

## Arguments

Parse from `$ARGUMENTS` (positional `$1` expansion is not stable across
runtimes):

- **findings path** (first positional, required): `TRIAGE.json` (preferred),
  `findings.json`, or a run directory containing one.
- `--repo PATH` (default cwd): the target codebase, read-only.
- `--only IDS`: comma-separated finding ids to verify (e.g. `f001,f004`).
  Default: every eligible finding (see Step 1).
- `--with-patch DIR`: a `PATCHES/` directory from `bughunt-patch`. When given,
  each verified PoC is re-run against a patched copy to confirm the fix
  (Step 3b).
- `--jobs N` (default 3): max PoCs built/run concurrently.
- `--timeout S` (default 60): per-PoC wall-clock limit inside the sandbox.
- `--no-sandbox`: run PoCs without isolation. Refused by default; requires an
  explicit acknowledgement that the target is a disposable lab environment.

## Step 0 — Setup and safety

### 0a. Resolve inputs

Resolve the findings path and `--repo`. If `--repo` doesn't exist or the
findings file is unparseable, stop with an error. Read the findings (Step 1
describes selection).

### 0b. Enforce the "untouched source" invariant

Do **not** run PoCs against the working `--repo`. Instead:

1. Copy the target to a throwaway dir once:
   `bash run-sandboxed.sh --prepare <repo> <workdir>/target`
   (this rsyncs the tree, drops `.git`, and marks it read-only).
2. All PoCs are built/run against `<workdir>/target`, which the sandbox mounts
   **read-only**. PoC files, build outputs, and logs go under
   `<workdir>/poc/bug_NN/`, never inside the target tree.

If an agent needs to build the target (compile a C library, `npm install`),
that happens in the writable scratch dir against the read-only source — a
build that requires editing tracked source files is itself a signal the PoC
is cheating, so treat a source-write attempt as a failed verification.

### 0c. Select the sandbox

Run `bash run-sandboxed.sh --detect`. It reports the first available of
`bwrap` (bubblewrap), `unshare` (userns + net ns), `firejail`, or `docker`
— ordered by the strength of their read-only guarantee (all four deny
network; `bwrap`/`firejail`/`docker` add a true read-only bind of the
target, `unshare` relies on the `--prepare` chmod plus the Step 3 checksum).

- A mechanism is found → use it for every PoC run.
- None found → **do not silently run unsandboxed.** Report it and stop, unless
  `--no-sandbox` was passed AND you have confirmed the target is a disposable
  lab. Record `sandbox: "none"` on every result so the report never overstates
  isolation.

## Step 1 — Select findings to verify

From `TRIAGE.json`, take findings with `verdict == "true_positive"` and
`verify_verdict` in `{exploitable, needs_manual_test}`. Skip
`false_positive`, `duplicate`, `mitigated`, and unlocatable findings — record
them in the output as `skipped` with the reason, don't drop them.

- `exploitable` findings are the primary targets: a PoC should reproduce them.
- `needs_manual_test` findings are exactly what this skill exists for — triage
  couldn't settle them statically; execution can.

From `findings.json` (report schema) instead: take entries whose
`execution.payloads` / `execution.expected_result` are populated; those fields
are the PoC spec. Honor `--only` if given. Assign `bug_NN` ids in triage rank
order.

## Step 2 — Write each PoC as a test (against untouched source)

Spawn one Task subagent per selected finding, `subagent_type:
"general-purpose"`, up to `--jobs` concurrent, each with the brief below.
**Set `subagent_type`; never fork** — a fork inherits every other finding's
context and the PoCs bleed together.

### PoC-author brief (per finding)

```
You are writing a proof-of-concept for ONE security finding that a triage
step already judged real. Your PoC must be a TEST that runs against the
UNTOUCHED target source and produces an OBSERVABLE signal when the
vulnerability triggers. You are proving the bug exists, in a sandbox, for
authorized verification — not weaponizing it.

TARGET (read-only): {workdir}/target   — you MAY read it; you may NOT modify
any file inside it. Write your PoC and any scaffolding under:
  {workdir}/poc/{bug_id}/

FINDING:
  id: {id}   file: {file}:{line}   category: {category}
  threat_model: {threat_model}
  title: {title}
  description: {description}
  exploit_scenario / expected_result: {exploit_scenario or expected_result}
  reachability evidence: {first_links}

PROCEDURE:
1. Read the cited code and the call path in {workdir}/target. Identify the
   real entry point an attacker (per threat_model) would hit — a function to
   call, an HTTP handler to POST to, a file the program parses, a CLI arg.
2. Write the PoC OUTSIDE the target tree, under {workdir}/poc/{bug_id}/. It
   must exercise the REAL code (import the module, link the library, spawn the
   built binary, start the server and send a request) — not a reimplementation
   of the buggy logic. If you re-implement the bug, you prove nothing.
3. Define the SUCCESS SIGNAL precisely and make it machine-checkable:
   - memory-safety: an AddressSanitizer/UBSan report in stderr, a SIGSEGV/
     SIGABRT, or a nonzero-but-specific crash (build the target with
     `-fsanitize=address` in the scratch dir if it's C/C++).
   - injection/RCE: a marker only the injection could produce (a sentinel
     file created, a sentinel string echoed, `id` output).
   - auth bypass: a protected resource returned to an unauthenticated caller.
   - SQLi/data exposure: a row/secret returned that the caller shouldn't see.
   Prefer a signal your test can assert on and exit accordingly.
4. Write a runner: {workdir}/poc/{bug_id}/run.sh that builds (if needed) and
   runs the PoC, exits 0 ONLY when the success signal is observed, and prints
   the signal text to stdout/stderr. It must not reach the network.

OUTPUT (exactly this block, then stop):
  POC_DIR: {workdir}/poc/{bug_id}/
  ENTRYPOINT: run.sh
  BUILD: <one-line build command, or "none">
  SUCCESS_SIGNAL: <the exact string/condition run.sh checks for>
  KIND: <asan_crash|signal_crash|marker_string|http_status|db_leak|other>
  NOTES: <anything the runner needs; e.g. "requires python3.11, pip deps vendored">
```

Record each returned block. If a subagent reports it could not build a PoC
that touches real code (only a reimplementation), mark the finding
`inconclusive` with reason `no_real_poc` — do NOT run a reimplementation.

## Step 3 — Execute each PoC in the sandbox

For each PoC with a runner, execute it:

```
bash run-sandboxed.sh --run <sandbox> \
  --root {workdir}/target \
  --work {workdir}/poc/{bug_id} \
  --timeout {timeout} \
  -- bash {workdir}/poc/{bug_id}/run.sh
```

The script mounts `{workdir}/target` read-only, gives `{work}` as the only
writable path, denies network, applies ulimits, and enforces the timeout.
Capture exit code, stdout, and stderr to `{work}/run.log`.

**Read-only strength differs by mechanism.** `bwrap`, `firejail`, and
`docker` give a true read-only bind of the target. `unshare` runs the PoC as
a userns fake-root, so it relies on the `chmod a-w` from `--prepare`, which a
determined PoC could undo. So regardless of mechanism, **checksum the target
before and after every run** and treat any change as cheating:

```
before=$(find {workdir}/target -type f -exec sha256sum {} + | sort | sha256sum)
# ... run the PoC ...
after=$(find {workdir}/target -type f -exec sha256sum {} + | sort | sha256sum)
```

If `before != after`, the PoC modified the untouched source → mark the
finding `inconclusive`, reason `modified_source`, and do not count it as
verified. (When available, prefer `bwrap` over `unshare` for the hard
read-only bind; `run-sandboxed.sh --detect` lists them in that order.)

**Classify from the captured output, not the exit code alone** (rule 2 up
top):

- `execution_verified` — the declared `SUCCESS_SIGNAL` is present in the
  captured output / the sanitizer fired / the marker appeared. Attach the
  matched evidence line(s).
- `not_reproduced` — the runner completed without the success signal. The
  finding may still be real (the PoC could be wrong), so note that; but it did
  not reproduce here.
- `inconclusive` — the runner hit the timeout, failed to build, needed the
  network, or tried to write into the read-only target. Record which.

Never upgrade a `not_reproduced`/`inconclusive` to verified because the static
argument was convincing — the whole point is that execution is the arbiter.

## Step 3b — Confirm the patch (only if `--with-patch DIR`)

For each `execution_verified` finding that has a patch in `DIR`
(`bug_NN/patch.diff`):

1. Copy the untouched target again into `{workdir}/patched-{bug_id}`,
   `git apply` (or `patch -p1`) the diff there. If it doesn't apply cleanly,
   record `patch_confirmed: false`, reason `patch_did_not_apply`.
2. Re-run the identical PoC against the patched copy in the sandbox.
3. `patch_confirmed: true` iff the success signal is now ABSENT (the bug is
   closed) AND the runner otherwise completes (the patch didn't just break the
   build). Attach the before/after signal lines.

This is the double-confirmation the Cloudflare methodology recommends: the PoC
fails on `main`, passes after the fix — evidence both that the bug is real and
that the patch works.

## Step 4 — Write output

Write to the findings directory (or `--repo` if that's where the run lives):

**`VERIFY.json`:**

```json
{
  "verified_at": "<iso8601>",
  "repo": "<repo>",
  "sandbox": "unshare|bwrap|firejail|docker|none",
  "summary": {
    "selected": 0, "execution_verified": 0, "not_reproduced": 0,
    "inconclusive": 0, "skipped": 0, "patch_confirmed": 0
  },
  "results": [
    {
      "bug_id": "bug_01",
      "finding_id": "f001",
      "file": "src/parse.c", "line": 88,
      "category": "heap-buffer-overflow",
      "status": "execution_verified|not_reproduced|inconclusive|skipped",
      "kind": "asan_crash",
      "success_signal": "READ of size 4 ... heap-buffer-overflow",
      "evidence": "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...",
      "poc_dir": "VERIFY/bug_01/",
      "sandbox": "unshare",
      "patch_confirmed": true,
      "notes": "..."
    }
  ]
}
```

**`VERIFY.md`** — one section per result: status badge, the PoC command, the
success signal, the evidence excerpt, and (if checked) the patch-confirmation
before/after. Copy each PoC's files into `VERIFY/bug_NN/` alongside `run.log`
so the report and a human reviewer can re-run them.

## Step 5 — Hand back

Tell the user:

1. Counts: N selected → V execution-verified, R not reproduced, I
   inconclusive, S skipped; P patches confirmed (if `--with-patch`).
2. The verified findings, one line each with their success signal.
3. Sandbox used (or the `none` warning).
4. Next step: the report phase (`bughunt-audit-report`) will show
   `execution_verified` badges; `bughunt-exploit-payloads` can turn verified
   PoCs into shareable repro cards.

## Constraints

- **Sandboxed execution only** (unless `--no-sandbox` on a lab target, loudly
  recorded). No network from any PoC. Read-only target; writable scratch only.
- **Untouched source is mechanically enforced** — a PoC that modifies the
  target, or only re-implements the buggy logic, is not a verification.
- **The signal decides**, not the exit code. Classify captured output.
- **Authorized targets only.** Local checkout / lab / active engagement.
  SSRF/exfil PoCs point at your own canary. Never a third-party live system.
- Findings this skill can't reproduce are **not** downgraded to false
  positives — `not_reproduced` is its own state; triage's verdict stands
  until a human decides otherwise.

## Provenance

The execution-verification model — PoC-as-test against untouched source, an
`unshare`-based sandbox with network denied, verdict from the observed signal,
and the PoC-fails-then-patch-passes double check — is adapted from
Cloudflare's [_Build your own vulnerability
harness_](https://blog.cloudflare.com/build-your-own-vulnerability-harness/)
(the VDH Hunt/Validation stages). It is the in-repo counterpart to the
execution-verified `vuln-pipeline` the read-only skills point at, packaged as
a skill that consumes this pipeline's `TRIAGE.json`. See
[/NOTICES.md](../../../NOTICES.md).
