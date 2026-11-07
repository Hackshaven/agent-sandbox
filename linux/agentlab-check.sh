#!/usr/bin/env bash
# agentlab-check: isolation checks, adapted from Anthropic's "verify isolation
# yourself" table. Run as root.
#
#   On the gateway:  sudo agentlab-check gateway
#   On the sandbox:  sudo agentlab-check sandbox [--model-call] [--model ID]
#
# Sandbox mode is meant for the Hyper-V console (it briefly adds a default route
# to prove the gateway refuses to route). When every sandbox check passes it
# records a marker that "sandbox-setup.sh finalize" requires.
set -uo pipefail

ROLE="${1:-}"; shift || true
MODEL_CALL=0 MODEL=claude-opus-5-5
while [[ $# -gt 0 ]]; do
  case "$1" in
    --model-call) MODEL_CALL=1; shift ;;
    --model) MODEL="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

GW_IP=10.77.0.1 SBX_IP=10.77.0.10 PORT=8080
LOG_DIR=/var/log/agentlab
MIN_CLAUDE=2.1.257
PASS=0 FAIL=0 WARN=0
pass() { printf '  PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }
warn() { printf '  WARN  %s\n' "$*"; WARN=$((WARN + 1)); }
t()    { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
tn()   { local what="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$what"; else pass "$what"; fi; }
section() { printf '\n%s\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 $ROLE" >&2; exit 2; }

# Run a command as the agent with the same environment SSH logins get.
as_agent() { sudo -u agent -H bash -c 'set -a; . /etc/environment; set +a; cd "$HOME"; '"$1"; }

version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

check_gateway() {
  local lab_if
  lab_if="$(ip -4 -o addr show | awk -v ip="$GW_IP/24" '$4 == ip {print $2; exit}')"

  section "Network"
  [[ -n "$lab_if" ]] && pass "$GW_IP/24 is on $lab_if" || fail "$GW_IP/24 is not configured on any interface"
  t  "IP forwarding is off" test "$(cat /proc/sys/net/ipv4/ip_forward)" = 0
  t  "IPv6 forwarding is off" test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0
  if [[ -n "$lab_if" ]]; then
    tn "no IPv6 address on $lab_if" bash -c "ip -6 addr show dev $lab_if | grep -q inet6"
  fi
  t  "internet reachable from the gateway (api.anthropic.com)" \
     curl -sS -o /dev/null --max-time 10 https://api.anthropic.com/

  section "Firewall"
  t  "nftables service is active" systemctl is-active -q nftables
  t  "agentlab table is loaded" nft list table inet agentlab
  local rules; rules="$(nft list table inet agentlab 2>/dev/null)"
  t  "only $SBX_IP -> :$PORT is accepted from the lab" grep -q "ip saddr $SBX_IP tcp dport $PORT ct state new accept" <<<"$rules"
  t  "forward chain drops by default" grep -Eq 'hook forward priority (0|filter); policy drop' <<<"$rules"
  t  "non-gateway destinations from the lab are dropped" grep -q "ip daddr != $GW_IP drop" <<<"$rules"

  section "Credential proxy"
  t  "nginx is active" systemctl is-active -q nginx
  t  "nginx config is valid" nginx -t -q
  local listeners; listeners="$(ss -Hltn "sport = :$PORT" | awk '{print $4}')"
  t  "proxy listens on $GW_IP:$PORT" grep -qx "$GW_IP:$PORT" <<<"$listeners"
  tn "nothing else listens on :$PORT" grep -qvx "$GW_IP:$PORT" <<<"$listeners"
  t  "default nginx site is disabled" test ! -e /etc/nginx/sites-enabled/default
  local tf=/etc/nginx/agentlab-token.conf
  t  "token file exists and is not empty" test -s "$tf"
  t  "token file is root-owned, mode 600" test "$(stat -c '%U %a' "$tf" 2>/dev/null)" = "root 600"
  t  "client body limit raised for long requests" grep -q client_max_body_size /etc/nginx/sites-available/agentlab
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$GW_IP:$PORT/")"
  [[ "$code" == 403 ]] && pass "non-model path returns 403" || fail "non-model path returned ${code:-nothing} (want 403)"

  section "Logs"
  t  "$LOG_DIR exists" test -d "$LOG_DIR"
  t  "egress-deny.log is being written by rsyslog" test -f "$LOG_DIR/egress-deny.log"
  t  "rsyslog routes AGENTLAB- lines" grep -q AGENTLAB- /etc/rsyslog.d/30-agentlab.conf
  t  "logrotate keeps 45 days" grep -q 'rotate 45' /etc/logrotate.d/agentlab
  t  "run folders are pruned daily" test -x /etc/cron.daily/agentlab-prune
  if [[ -s "$LOG_DIR/credproxy.log" ]]; then
    local refused
    refused="$(awk '$5 != 200 {print $3, $4, $5}' "$LOG_DIR/credproxy.log" | sort | uniq -c | sort -rn | head -10)"
    if [[ -n "$refused" ]]; then
      warn "proxy has refused these (method path status). Allow a path only if it's a model call, in gateway-setup.sh:"
      sed 's/^/          /' <<<"$refused"
    fi
  fi
  if [[ -s "$LOG_DIR/egress-deny.log" ]]; then
    printf '        last firewall denies:\n'; tail -5 "$LOG_DIR/egress-deny.log" | sed 's/^/          /'
  fi
}

check_sandbox() {
  local ifs
  section "Network"
  tn "no default route" bash -c 'ip route show default | grep -q .'
  tn "no IPv4 routes beyond 10.77.0.0/24, in any routing table" \
     bash -c "ip -4 route show table all | grep -vE '^(local|broadcast) |^10\.77\.0\.0/24 dev ' | grep -q ."
  tn "no IPv6 addresses (including link-local)" bash -c 'ip -6 addr show | grep -q inet6'
  t  "address is $SBX_IP/24" bash -c "ip -4 -o addr show | grep -q ' $SBX_IP/24 '"
  ifs="$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | cut -d@ -f1)"
  [[ "$(wc -w <<<"$ifs")" == 1 ]] && pass "one network interface ($ifs)" || fail "expected one interface, found: $ifs"
  tn "DNS does not resolve (api.anthropic.com)" getent hosts api.anthropic.com
  tn "no direct HTTPS to the internet (1.1.1.1)" curl -sk -o /dev/null --max-time 5 https://1.1.1.1/
  tn "no direct HTTPS to api.anthropic.com" curl -s -o /dev/null --max-time 5 https://api.anthropic.com/
  tn "gateway SSH port is closed to the sandbox" timeout 4 bash -c "exec 3<>/dev/tcp/$GW_IP/22"
  t  "gateway proxy port is open" timeout 4 bash -c "exec 3<>/dev/tcp/$GW_IP/$PORT"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$GW_IP:$PORT/")"
  [[ "$code" == 403 ]] && pass "proxy refuses non-model paths (403)" || fail "proxy returned ${code:-nothing} for / (want 403)"

  # Prove the gateway won't route even if the sandbox tries.
  ip route add default via "$GW_IP" 2>/dev/null
  tn "gateway refuses to route (temporary default route added)" curl -sk -o /dev/null --max-time 5 https://1.1.1.1/
  ip route del default via "$GW_IP" 2>/dev/null
  tn "temporary route removed" bash -c 'ip route show default | grep -q .'

  section "Host coupling"
  tn "no shared or network filesystems mounted" \
     bash -c "awk '\$3 ~ /^(9p|virtiofs|cifs|smb3|nfs|nfs4|fuse.*|drvfs|vboxsf)\$/' /proc/mounts | grep -q ."
  tn "hv_sock (Hyper-V sockets) not loaded" bash -c 'lsmod | grep -q "^hv_sock"'
  t  "hv_sock blocked from loading" grep -qs 'install hv_sock /bin/false' /etc/modprobe.d/agentlab.conf
  tn "Hyper-V file copy daemon not running" pgrep -x hv_fcopy_daemon
  tn "Hyper-V KVP daemon not running" pgrep -x hv_kvp_daemon

  section "Agent account"
  t  "user agent exists" id agent
  tn "agent is in no privileged group" bash -c "id -nG agent | grep -qwE 'sudo|docker|adm|lxd|admin|wheel|disk|root|libvirt|incus-admin'"
  tn "agent has no sudo rights" bash -c "sudo -l -U agent 2>/dev/null | grep -q '(.*)'"
  tn "no stored Claude login for agent" test -e /home/agent/.claude/.credentials.json
  tn "no SSH private keys in agent's home" bash -c "grep -rlsE 'BEGIN (OPENSSH|RSA|EC) PRIVATE KEY' /home/agent | grep -q ."
  tn "no Anthropic keys or tokens on disk" \
     bash -c "grep -rIlsE 'sk-ant-(api|oat|admin)[0-9]*-[A-Za-z0-9_-]{20,}' /home /etc /root /work /opt 2>/dev/null | grep -q ."
  local envout; envout="$(as_agent 'env' 2>/dev/null)"
  t  "ANTHROPIC_BASE_URL points at the proxy" grep -qx "ANTHROPIC_BASE_URL=http://$GW_IP:$PORT" <<<"$envout"
  t  "CLAUDE_CODE_OAUTH_TOKEN is the placeholder" grep -q '^CLAUDE_CODE_OAUTH_TOKEN=placeholder-' <<<"$envout"
  tn "ANTHROPIC_API_KEY is not set" grep -q '^ANTHROPIC_API_KEY=' <<<"$envout"
  tn "agent can't edit /etc/environment" sudo -u agent test -w /etc/environment
  t  "SSH allows only agent from $GW_IP" grep -qs "AllowUsers agent@$GW_IP" /etc/ssh/sshd_config.d/00-agentlab.conf
  t  "SSH password logins are off" bash -c "sshd -T 2>/dev/null | grep -qx 'passwordauthentication no'"

  section "Claude Code"
  local cl; cl="$(command -v claude || true)"
  [[ -n "$cl" ]] && pass "claude is installed ($cl)" || fail "claude not on PATH"
  if [[ -n "$cl" ]]; then
    local owner; owner="$(stat -L -c %U "$cl")"
    [[ "$owner" == root ]] && pass "claude binary is root-owned" || warn "claude binary is owned by $owner (agent could modify it)"
    local v; v="$(as_agent 'claude --version' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [[ -z "$v" ]]; then fail "claude --version failed for agent"
    elif version_ge "$v" "$MIN_CLAUDE"; then pass "Claude Code $v (>= $MIN_CLAUDE, default containment rules)"
    else fail "Claude Code $v is older than $MIN_CLAUDE"; fi
  fi
  local ms=/etc/claude-code/managed-settings.json
  t  "managed settings present" test -f "$ms"
  t  "managed settings root-owned, not agent-writable" bash -c "[ \"\$(stat -c %U $ms)\" = root ] && ! sudo -u agent test -w $ms"
  t  "managed settings are valid JSON" python3 -c "import json,sys; json.load(open('$ms'))"
  t  "auto mode is the default" python3 -c "import json; d=json.load(open('$ms')); assert d['permissions']['defaultMode']=='auto'"
  t  "bypass permissions mode is disabled" python3 -c "import json; d=json.load(open('$ms')); assert d['permissions']['disableBypassPermissionsMode']=='disable'"
  local amc; amc="$(as_agent 'claude auto-mode config' 2>/dev/null)"
  if grep -q 'Host containment' <<<"$amc"; then pass "auto mode config includes the lab's environment entries"
  else fail "'claude auto-mode config' doesn't show the lab's entries (check the managed-settings path for your version)"; fi
  if python3 -c "import json; d=json.load(open('$ms')); assert any('No network' in r for r in d['autoMode']['soft_deny'])" 2>/dev/null; then
    pass "No-network rule present (finalized)"
  else
    warn "No-network rule not added yet (sandbox-setup.sh finalize adds it after these checks pass)"
  fi

  if [[ $MODEL_CALL == 1 ]]; then
    section "Model call through the proxy"
    local out
    out="$(as_agent "cd /tmp && timeout 120 claude -p --model $MODEL --max-turns 1 'Reply with exactly: AGENTLAB-OK'" 2>&1)"
    if grep -q 'AGENTLAB-OK' <<<"$out"; then pass "model replied via the gateway"
    else fail "model call failed: $(head -c 300 <<<"$out" | tr '\n' ' ')"; fi
  else
    printf '\n  (skipped the model call; add --model-call once the gateway is up)\n'
  fi
}

case "$ROLE" in
  gateway) check_gateway ;;
  sandbox) check_sandbox ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac

printf '\n%d passed, %d failed, %d warnings\n' "$PASS" "$FAIL" "$WARN"
if [[ "$ROLE" == sandbox ]]; then
  if (( FAIL == 0 )) && [[ $MODEL_CALL == 1 ]]; then
    install -d -m 755 /var/lib/agentlab
    date -Is > /var/lib/agentlab/sandbox-checks-passed
    echo "Recorded a pass in /var/lib/agentlab/sandbox-checks-passed."
  else
    rm -f /var/lib/agentlab/sandbox-checks-passed
  fi
fi
(( FAIL == 0 ))
