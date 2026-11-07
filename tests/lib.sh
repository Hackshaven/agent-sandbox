# Shared helpers for the test scripts. Source, don't run.
# shellcheck shell=bash

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_SETUP="$REPO/linux/gateway-setup.sh"

T_PASS=0 T_FAIL=0
ok()   { printf '  ok    %s\n' "$*"; T_PASS=$((T_PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$*"; T_FAIL=$((T_FAIL + 1)); }
skip() { printf '  skip  %s\n' "$*"; }
check() {   # check "description" command...
  local what="$1"; shift
  if "$@"; then ok "$what"; else bad "$what"; fi
}
refuse() {  # refuse "description" command...   (passes when the command fails)
  local what="$1"; shift
  if "$@"; then bad "$what"; else ok "$what"; fi
}
finish() {
  printf '  %d passed, %d failed\n' "$T_PASS" "$T_FAIL"
  (( T_FAIL == 0 ))
}

# Print the body of the heredoc that starts on the line containing $1 in file $2.
heredoc_body() {
  awk -v start="$1" 'index($0, start) { f = 1; next } f && /^EOF$/ { exit } f' "$2"
}

# Render an unquoted heredoc from gateway-setup.sh with the given variable assignments.
render_heredoc() {   # render_heredoc "start line" "VAR=value ..."
  local start="$1" vars="$2" body
  body="$(heredoc_body "$start" "$GATEWAY_SETUP")"
  [[ -n "$body" ]] || { echo "heredoc not found: $start" >&2; return 1; }
  bash -c "$vars; cat <<EOF
$body
EOF"
}
