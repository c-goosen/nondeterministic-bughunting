#!/usr/bin/env bash
# run-semgrep.sh — offline-first semgrep directory scan for vuln-scan Step 0.
#
# Resolves <target> to a local directory (targets/<name>, repo-relative path, or
# absolute path), then scans that tree with bundled rules under semgrep/ — not
# --config auto (registry fetch + project telemetry).
#
# Usage:
#   bash run-semgrep.sh <target-dir-or-name> [--output <path>]
#
# Writes JSON to <target>/.semgrep.json by default.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RULES_DIR="$SCRIPT_DIR/semgrep"

# Hard wall-clock cap on the semgrep run. Semgrep can be slow on large trees,
# so this is generous (10 min, matching the scanner-timeout policy in
# SKILL.md) rather than the Bash tool's 120 s default. Override with
# SEMGREP_TIMEOUT (seconds); set to 0 to disable the cap entirely.
SEMGREP_TIMEOUT="${SEMGREP_TIMEOUT:-600}"

usage() {
  echo "Usage: run-semgrep.sh <target-dir-or-name> [--output <path>]" >&2
  exit 1
}

[[ $# -ge 1 ]] || usage

TARGET_ARG="$1"
shift
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || usage
      OUTPUT="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

resolve_target() {
  local arg="$1"
  if [[ -d "$arg" ]]; then
    cd "$arg" && pwd
    return 0
  fi
  if [[ -d "$REPO_ROOT/targets/$arg" ]]; then
    cd "$REPO_ROOT/targets/$arg" && pwd
    return 0
  fi
  if [[ -d "$REPO_ROOT/$arg" ]]; then
    cd "$REPO_ROOT/$arg" && pwd
    return 0
  fi
  echo "run-semgrep: target directory not found: $arg (tried ., targets/$arg, $REPO_ROOT/$arg)" >&2
  return 1
}

if ! command -v semgrep >/dev/null 2>&1; then
  echo "run-semgrep: semgrep not on PATH (install via setup-tools.sh)" >&2
  exit 1
fi

TARGET="$(resolve_target "$TARGET_ARG")"
[[ -n "$OUTPUT" ]] || OUTPUT="$TARGET/.semgrep.json"

if [[ ! -d "$RULES_DIR" ]]; then
  echo "run-semgrep: missing bundled rules at $RULES_DIR" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

# Directory scan only — no registry auto-config.
# Older semgrep builds may ignore --output; capture JSON from stdout.
# Wrap in `timeout` (when available and enabled) so a runaway scan is killed
# with SIGKILL 5 s after the soft deadline instead of hanging forever.
TIMEOUT_PREFIX=()
if [[ "$SEMGREP_TIMEOUT" != "0" ]] && command -v timeout >/dev/null 2>&1; then
  TIMEOUT_PREFIX=(timeout -k 5 "$SEMGREP_TIMEOUT")
fi

set +e
"${TIMEOUT_PREFIX[@]}" semgrep scan \
  --config "$RULES_DIR" \
  --metrics off \
  --json --quiet \
  --exclude node_modules \
  --exclude .git \
  --exclude dist \
  --exclude build \
  --exclude vendor \
  --exclude coverage \
  --exclude .next \
  --exclude .turbo \
  "$TARGET" >"$OUTPUT" 2>/dev/null
rc=$?
set -e

# 124 = timeout killed the scan (soft deadline); 137 = SIGKILL after -k grace.
if [[ $rc -eq 124 || $rc -eq 137 ]]; then
  echo "run-semgrep: semgrep timed out after ${SEMGREP_TIMEOUT}s (raise SEMGREP_TIMEOUT or narrow the target)" >&2
  exit "$rc"
fi
# 0 = clean, 1 = findings (expected), 2 = config/parse error (fail).
if [[ $rc -eq 2 ]]; then
  echo "run-semgrep: semgrep failed (exit $rc)" >&2
  exit "$rc"
fi
if [[ ! -s "$OUTPUT" ]]; then
  echo '{"results":[],"errors":[],"paths":{"scanned":[]}}' >"$OUTPUT"
fi

echo "run-semgrep: scanned $TARGET -> $OUTPUT (config=$RULES_DIR)"
