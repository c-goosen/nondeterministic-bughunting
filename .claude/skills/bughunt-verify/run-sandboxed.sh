#!/usr/bin/env bash
#
# run-sandboxed.sh — isolation wrapper for bughunt-verify PoC execution.
#
# The security properties this enforces, in priority order:
#   1. No network       (a PoC must never reach a live host)
#   2. Read-only target (the "untouched source" invariant)
#   3. Resource caps    (CPU / file-size / no core spam) + hard timeout
#
# Subcommands:
#   --detect
#       Print the first available mechanism: unshare | bwrap | firejail |
#       docker | none. Exit 0.
#
#   --prepare <src> <dst>
#       Copy target <src> to <dst> (excluding .git), then mark <dst>
#       read-only. This is the copy every PoC runs against.
#
#   --run <mechanism> --root <ro-dir> --work <rw-dir> [--timeout S]
#         [--image IMG] -- <cmd...>
#       Run <cmd> with network denied, <ro-dir> read-only, <rw-dir> the only
#       writable path, ulimits applied, and a wall-clock timeout. stdout and
#       stderr pass through; exit code is the command's (124 on timeout).
#
# Nothing here executes target code itself — it wraps a command the caller
# supplies. Authorization and PoC contents are the caller's responsibility.

set -euo pipefail

die() { echo "run-sandboxed: $*" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Resource limits + timeout applied INSIDE every mechanism, so the guarantee
# is uniform regardless of which sandbox is available.
CPU_LIMIT=${BUGHUNT_CPU_LIMIT:-120}     # seconds of CPU time
FSIZE_LIMIT=${BUGHUNT_FSIZE_LIMIT:-524288}  # blocks (~256MB) max file write
# Wall-clock cap per PoC when --timeout is not passed. Generous by default so a
# PoC that has to build/compile isn't cut off prematurely; override with
# BUGHUNT_TIMEOUT (seconds) or the --timeout flag.
DEFAULT_TIMEOUT=${BUGHUNT_TIMEOUT:-300}

# Emit a shell preamble that clamps resources, then execs the payload.
# Core dumps are disabled (ASAN reports to stderr; we don't want core spam),
# but sanitizer output is preserved.
limited_cmd() {
  local work="$1"; shift
  printf 'ulimit -t %s; ulimit -f %s; ulimit -c 0; cd %q || exit 3; exec "$@"' \
    "$CPU_LIMIT" "$FSIZE_LIMIT" "$work"
}

cmd_detect() {
  # Order = strength of the read-only guarantee, then availability. bwrap and
  # firejail give a true read-only bind of the target; unshare relies on the
  # chmod from --prepare (userns fake-root can undo it — callers must also
  # checksum the target before/after). All four deny network.
  if have bwrap; then echo bwrap
  elif have unshare && unshare -rn true 2>/dev/null; then echo unshare
  elif have firejail; then echo firejail
  elif have docker && docker info >/dev/null 2>&1; then echo docker
  else echo none; fi
}

cmd_prepare() {
  local src="$1" dst="$2"
  [ -d "$src" ] || die "prepare: source '$src' is not a directory"
  mkdir -p "$dst"
  if have rsync; then
    rsync -a --delete --exclude='.git' "$src"/ "$dst"/
  else
    # cp fallback: copy then strip .git
    cp -a "$src"/. "$dst"/
    rm -rf "$dst/.git"
  fi
  # Enforce the untouched-source invariant: read-only for everyone. The
  # sandbox layer re-enforces this with a read-only bind where it can, but
  # this makes a source write fail even under --no-sandbox.
  chmod -R a-w "$dst" 2>/dev/null || true
  echo "prepared read-only target at $dst"
}

cmd_run() {
  local mech="" root="" work="" timeout="$DEFAULT_TIMEOUT" image="alpine:latest"
  while [ $# -gt 0 ]; do
    case "$1" in
      --root)    root="$2"; shift 2;;
      --work)    work="$2"; shift 2;;
      --timeout) timeout="$2"; shift 2;;
      --image)   image="$2"; shift 2;;
      --)        shift; break;;
      unshare|bwrap|firejail|docker|none) mech="$1"; shift;;
      *) die "run: unexpected arg '$1'";;
    esac
  done
  [ -n "$mech" ] || die "run: mechanism required (unshare|bwrap|firejail|docker|none)"
  [ -n "$work" ] || die "run: --work required"
  [ $# -gt 0 ]   || die "run: no command after --"
  mkdir -p "$work"

  local pre; pre="$(limited_cmd "$work")"

  case "$mech" in
    unshare)
      # New user + net namespace: net ns has only a down loopback → no network.
      timeout -k 5 "$timeout" \
        unshare -rn -- bash -c "$pre" bash "$@"
      ;;
    bwrap)
      # Read-only view of the whole FS (so the target is read-only), then a
      # single writable bind for work. Do NOT --tmpfs /tmp: when the prepared
      # target/work live under /tmp that would hide them. Builds that need a
      # scratch tmp get TMPDIR inside work instead. Network namespace unshared.
      timeout -k 5 "$timeout" \
        bwrap --ro-bind / / --dev /dev --proc /proc \
              ${root:+--ro-bind "$root" "$root"} \
              --bind "$work" "$work" --setenv TMPDIR "$work" \
              --unshare-net --die-with-parent --chdir "$work" \
              -- bash -c "$pre" bash "$@"
      ;;
    firejail)
      # firejail timeout is hh:mm:ss — format all three fields so timeouts
      # of an hour or more aren't silently truncated.
      local hz; hz="$(printf '%02d:%02d:%02d' $((timeout/3600)) $(((timeout%3600)/60)) $((timeout%60)))"
      firejail --quiet --net=none --private-tmp \
               ${root:+--read-only="$root"} --whitelist="$work" \
               --timeout="$hz" \
               -- bash -c "$pre" bash "$@"
      ;;
    docker)
      # Best-effort: needs an image with the target's toolchain. --image
      # overrides the default. No network; ro target; rw work.
      timeout -k 5 "$timeout" \
        docker run --rm --network none \
          ${root:+-v "$root":"$root":ro} \
          -v "$work":"$work" -w "$work" \
          "$image" bash -c "$pre" bash "$@"
      ;;
    none)
      echo "run-sandboxed: WARNING running WITHOUT isolation (--no-sandbox)" >&2
      timeout -k 5 "$timeout" bash -c "$pre" bash "$@"
      ;;
    *) die "run: unknown mechanism '$mech'";;
  esac
}

[ $# -gt 0 ] || die "usage: --detect | --prepare <src> <dst> | --run <mech> --root R --work W [--timeout S] -- cmd..."
sub="$1"; shift
case "$sub" in
  --detect)  cmd_detect ;;
  --prepare) [ $# -eq 2 ] || die "prepare: need <src> <dst>"; cmd_prepare "$@" ;;
  --run)     cmd_run "$@" ;;
  *) die "unknown subcommand '$sub'";;
esac
