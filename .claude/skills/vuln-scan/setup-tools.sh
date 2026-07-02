#!/usr/bin/env bash
# setup-tools.sh — install the deterministic scanners the vuln-scan skill uses.
#
#   semgrep      pattern-based SAST            https://github.com/semgrep/semgrep
#   osv-scanner  dependency CVEs (OSV.dev)     https://github.com/google/osv-scanner
#   grype        image/filesystem CVEs         https://github.com/anchore/grype
#   gitleaks     secrets                       https://github.com/gitleaks/gitleaks
#   checkov      IaC misconfig                 https://github.com/bridgecrewio/checkov
#
# Idempotent: skips anything already on PATH. Picks an installer per tool based
# on what's available (pipx/pip, brew, go, or the vendor install script).
# Re-run safely; pass --check to only report status without installing.
set -uo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '  %s\n' "$*"; }
ok()   { printf '\033[32mok\033[0m   %s\n' "$*"; }
miss() { printf '\033[33mmiss\033[0m %s\n' "$*"; }
fail() { printf '\033[31mfail\033[0m %s\n' "$*"; }

OS="$(uname -s)"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"

# `go install` drops binaries in $GOPATH/bin, which is often not on PATH.
# Symlink the named binary into ~/.local/bin (commonly on PATH) so it resolves.
link_go_bin() {
  local name="$1" gobin
  gobin="$(go env GOPATH 2>/dev/null)/bin"
  if [[ -x "$gobin/$name" ]] && ! have "$name"; then
    ln -sf "$gobin/$name" "$LOCAL_BIN/$name"
    note "$name linked into $LOCAL_BIN (ensure it is on PATH)"
  fi
}

install_semgrep() {
  have semgrep && { ok "semgrep ($(semgrep --version 2>/dev/null | head -1))"; return; }
  miss "semgrep — installing"
  if have pipx; then pipx install semgrep
  elif have pip3; then pip3 install --user semgrep
  elif have brew; then brew install semgrep
  else fail "semgrep: need pipx, pip3, or brew"; return 1; fi
}

install_osv() {
  have osv-scanner && { ok "osv-scanner ($(osv-scanner --version 2>/dev/null | head -1))"; return; }
  miss "osv-scanner — installing"
  if have brew; then brew install osv-scanner
  elif have go; then go install github.com/google/osv-scanner/cmd/osv-scanner@latest; link_go_bin osv-scanner
  else fail "osv-scanner: install Go or Homebrew, or grab a release binary from https://github.com/google/osv-scanner/releases"; return 1; fi
}

install_grype() {
  have grype && { ok "grype ($(grype version 2>/dev/null | awk '/Version:/{print $2}'))"; return; }
  miss "grype — installing"
  if have brew; then brew install grype
  else
    # Official vendor installer → ~/.local/bin (no root).
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b "$LOCAL_BIN" \
      && note "grype installed to $LOCAL_BIN (ensure it is on PATH)"
  fi
}

install_gitleaks() {
  have gitleaks && { ok "gitleaks ($(gitleaks version 2>/dev/null))"; return; }
  miss "gitleaks — installing"
  if have brew; then brew install gitleaks
  elif have go; then go install github.com/gitleaks/gitleaks/v8@latest; link_go_bin gitleaks
  else fail "gitleaks: install Go or Homebrew, or grab a release binary from https://github.com/gitleaks/gitleaks/releases"; return 1; fi
}

# checkov is a Python tool. Prefer pipx/brew; otherwise install into the user
# site, coping with PEP 668 ("externally-managed") environments that lack pip
# and venv, then ensure a `checkov` shim exists on PATH (some such installs
# skip the console script).
install_checkov() {
  have checkov && { ok "checkov ($(checkov --version 2>/dev/null | head -1))"; return; }
  miss "checkov — installing"
  if have pipx; then pipx install checkov
  elif have brew; then brew install checkov
  elif have python3; then
    # Bootstrap pip into the user site if the interpreter has none.
    if ! python3 -m pip --version >/dev/null 2>&1; then
      curl -sSfL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py \
        && python3 /tmp/get-pip.py --user --break-system-packages >/dev/null 2>&1
    fi
    python3 -m pip install --user --break-system-packages --quiet checkov || { fail "checkov: pip install failed"; return 1; }
    # If pip didn't drop a console script, shim it to the module entry point.
    if ! have checkov && python3 -c 'import checkov' 2>/dev/null; then
      printf '#!/usr/bin/env bash\nexec python3 -m checkov.main "$@"\n' > "$LOCAL_BIN/checkov"
      chmod +x "$LOCAL_BIN/checkov"
      note "checkov shim written to $LOCAL_BIN/checkov"
    fi
  else fail "checkov: need pipx, brew, or python3"; return 1; fi
}

TOOLS="semgrep osv-scanner grype gitleaks checkov"

echo "vuln-scan tool check (OS: $OS)"
if [[ $CHECK_ONLY -eq 1 ]]; then
  for t in $TOOLS; do
    have "$t" && ok "$t" || miss "$t (not installed)"
  done
  exit 0
fi

rc=0
install_semgrep  || rc=1
install_osv      || rc=1
install_grype    || rc=1
install_gitleaks || rc=1
install_checkov  || rc=1

echo
echo "summary:"
for t in $TOOLS; do
  have "$t" && ok "$t" || fail "$t still missing — see notes above"
done
exit $rc
