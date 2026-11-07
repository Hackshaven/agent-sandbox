#!/usr/bin/env bash
# gateway-setup.sh: turn a fresh Ubuntu Server 24.04 VM into the agent lab gateway.
#
# Run once, as root, on agentlab-gw:   sudo ./gateway-setup.sh [--inside-if eth1]
# Safe to re-run: it rewrites its own config files and leaves everything else alone.
#
# What it sets up:
#   - static 10.77.0.1/24 on the AgentLab interface, IPv6 off there, no forwarding
#   - nftables: the sandbox may reach 10.77.0.1:8080 and nothing else; the rest is
#     dropped and logged
#   - nginx credential proxy on 10.77.0.1:8080 that forwards only model calls and
#     adds your Claude token (prompted for, stored root-only)
#   - logs under /var/log/agentlab, 45-day retention
#   - an SSH key for launching runs, and the agentlab-* commands in /usr/local/bin
set -euo pipefail

GW_IP=10.77.0.1
SBX_IP=10.77.0.10
PROXY_PORT=8080
LOG_DIR=/var/log/agentlab
RETAIN_DAYS=45
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INSIDE_IF=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --inside-if) INSIDE_IF="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] || die "Run with sudo from your normal admin account, not as root directly."
OPERATOR="$SUDO_USER"
OPERATOR_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)"
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die "This script targets Ubuntu Server 24.04."

# ---------------------------------------------------------------- interfaces
say "Finding the AgentLab interface"
OUTSIDE_IF="$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[[ -n "$OUTSIDE_IF" ]] || die "No default route. The gateway needs internet on its Default Switch adapter."
if [[ -z "$INSIDE_IF" ]]; then
  mapfile -t candidates < <(
    for d in /sys/class/net/*; do
      n="$(basename "$d")"
      [[ "$n" == lo || "$n" == "$OUTSIDE_IF" ]] && continue
      [[ -e "$d/device" ]] || continue          # physical (virtual hardware) NICs only
      echo "$n"
    done)
  [[ ${#candidates[@]} -eq 1 ]] || die "Expected one extra NIC, found ${#candidates[@]} (${candidates[*]:-none}). Re-run with --inside-if NAME."
  INSIDE_IF="${candidates[0]}"
fi
[[ "$INSIDE_IF" != "$OUTSIDE_IF" ]] || die "--inside-if is the internet-facing interface."
INSIDE_MAC="$(cat "/sys/class/net/$INSIDE_IF/address")"
note "internet side: $OUTSIDE_IF    AgentLab side: $INSIDE_IF ($INSIDE_MAC)"
note "Check that MAC against: Get-VMNetworkAdapter -VMName agentlab-gw   (the one on AgentLab)"

# ---------------------------------------------------------------- packages
say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q nginx nftables rsyslog logrotate openssh-client python3 curl ca-certificates
KFLAVOR="$(uname -r | sed -E 's/^[0-9.-]+-//')"     # generic, virtual, ...
apt-get install -y -q "linux-cloud-tools-${KFLAVOR:-generic}" >/dev/null 2>&1 \
  || note "linux-cloud-tools not installed; Windows may not see this VM's IP (use agentlab-gw.mshome.net or -GatewayHost)."

# ---------------------------------------------------------------- network
say "Configuring $INSIDE_IF as $GW_IP/24"
cat > /etc/netplan/60-agentlab.yaml <<EOF
# Written by gateway-setup.sh. AgentLab side: static, no gateway, no IPv6.
# Same ID as the interface, so it overrides anything the installer wrote for it.
network:
  version: 2
  ethernets:
    $INSIDE_IF:
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      addresses: [$GW_IP/24]
EOF
chmod 600 /etc/netplan/60-agentlab.yaml

cat > /etc/sysctl.d/60-agentlab.conf <<EOF
# Written by gateway-setup.sh
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.$INSIDE_IF.disable_ipv6 = 1
# Lets nginx bind 10.77.0.1 at boot even if the address isn't up yet.
net.ipv4.ip_nonlocal_bind = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF
sysctl -q --system
netplan apply
sleep 2
ip -4 addr show dev "$INSIDE_IF" | grep -q "$GW_IP/24" || die "$INSIDE_IF did not get $GW_IP."

# ---------------------------------------------------------------- firewall
say "Writing the nftables firewall"
RATE="limit rate 50/second burst 200 packets"
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# Written by gateway-setup.sh. The sandbox ($SBX_IP) may open connections to
# $GW_IP:$PROXY_PORT and nothing else. Everything else it sends is logged and dropped.
flush ruleset

table inet agentlab {
  chain prerouting {
    type filter hook prerouting priority -150; policy accept;
    # Nothing from the lab network may be routed anywhere.
    iifname "$INSIDE_IF" meta nfproto ipv6 $RATE log prefix "AGENTLAB-ROUTE-DENY: "
    iifname "$INSIDE_IF" meta nfproto ipv6 drop
    iifname "$INSIDE_IF" ip daddr != $GW_IP $RATE log prefix "AGENTLAB-ROUTE-DENY: "
    iifname "$INSIDE_IF" ip daddr != $GW_IP drop
    # The proxy address answers only on the lab interface.
    iifname != { "lo", "$INSIDE_IF" } ip daddr $GW_IP drop
  }
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "$INSIDE_IF" ct state established,related accept
    iifname "$INSIDE_IF" ip saddr $SBX_IP tcp dport $PROXY_PORT ct state new accept
    iifname "$INSIDE_IF" $RATE log prefix "AGENTLAB-DENY: "
    iifname "$INSIDE_IF" drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    $RATE log prefix "AGENTLAB-FWD-DENY: "
  }
  chain output {
    type filter hook output priority 0; policy accept;
    oifname "$INSIDE_IF" ct state established,related accept
    oifname "$INSIDE_IF" ip daddr $SBX_IP tcp dport 22 accept
    oifname "$INSIDE_IF" $RATE log prefix "AGENTLAB-OUT-DENY: "
    oifname "$INSIDE_IF" drop
  }
}
EOF
nft -c -f /etc/nftables.conf
systemctl enable -q nftables
systemctl restart nftables

# ---------------------------------------------------------------- logging
say "Setting up logs in $LOG_DIR"
install -d -m 0750 -o root -g adm "$LOG_DIR"
install -d -m 0750 -o "$OPERATOR" -g adm "$LOG_DIR/runs"
[[ -f "$LOG_DIR/egress-deny.log" ]] || install -m 0640 -o syslog -g adm /dev/null "$LOG_DIR/egress-deny.log"
[[ -f "$LOG_DIR/credproxy.log" ]] || install -m 0640 -o root -g adm /dev/null "$LOG_DIR/credproxy.log"
if ! id -nG "$OPERATOR" | grep -qw adm; then
  usermod -aG adm "$OPERATOR"
  note "Added $OPERATOR to group adm (to read logs). Log out and back in for it to apply."
fi

cat > /etc/rsyslog.d/30-agentlab.conf <<EOF
# Written by gateway-setup.sh: firewall denies go to their own file.
:msg, contains, "AGENTLAB-" $LOG_DIR/egress-deny.log
& stop
EOF
systemctl restart rsyslog

cat > /etc/logrotate.d/agentlab <<EOF
# Written by gateway-setup.sh
$LOG_DIR/*.log {
    daily
    rotate $RETAIN_DAYS
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        [ -f /run/nginx.pid ] && kill -USR1 "\$(cat /run/nginx.pid)"
        systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF
cat > /etc/cron.daily/agentlab-prune <<EOF
#!/bin/sh
# Written by gateway-setup.sh: drop run folders older than $RETAIN_DAYS days.
find $LOG_DIR/runs -mindepth 1 -maxdepth 1 -mtime +$RETAIN_DAYS -exec rm -rf {} +
EOF
chmod 755 /etc/cron.daily/agentlab-prune

# ---------------------------------------------------------------- token
say "Model token"
TOKEN_FILE=/etc/nginx/agentlab-token.conf
if [[ -s "$TOKEN_FILE" ]]; then
  note "A token is already stored. Press Enter to keep it, or paste a new one."
fi
note "Paste the token from 'claude setup-token' (input is hidden):"
read -r -s TOKEN || true
echo
if [[ -n "$TOKEN" ]]; then
  [[ "$TOKEN" =~ ^[A-Za-z0-9._-]+$ ]] || die "That doesn't look like a token (unexpected characters)."
  [[ "$TOKEN" == sk-ant-oat* ]] || note "Warning: setup tokens normally start with sk-ant-oat. Storing it anyway."
  ( umask 077; printf 'set $agentlab_token "%s";\n' "$TOKEN" > "$TOKEN_FILE" )
  unset TOKEN
elif [[ ! -s "$TOKEN_FILE" ]]; then
  die "No token stored. Re-run and paste one."
fi
chown root:root "$TOKEN_FILE"; chmod 600 "$TOKEN_FILE"

# ---------------------------------------------------------------- proxy
say "Writing the credential proxy"
cat > /etc/nginx/agentlab-upstream.conf <<'EOF'
# Written by gateway-setup.sh. Shared by every allowed model path.
set $agentlab_upstream https://api.anthropic.com;
proxy_pass $agentlab_upstream;
proxy_http_version 1.1;
proxy_set_header Host api.anthropic.com;
proxy_set_header Connection "";
proxy_set_header Authorization "Bearer $agentlab_token";
proxy_set_header x-api-key "";
proxy_set_header X-Forwarded-For "";
proxy_ssl_server_name on;
proxy_ssl_name api.anthropic.com;
proxy_ssl_verify on;
proxy_ssl_verify_depth 3;
proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
proxy_buffering off;
proxy_request_buffering off;
proxy_read_timeout 600s;
proxy_send_timeout 600s;
EOF

cat > /etc/nginx/sites-available/agentlab <<EOF
# Written by gateway-setup.sh. Model calls only; everything else gets 403.
# The log records client, method, path, status and size. Never headers or bodies.
log_format agentlab '\$time_iso8601 \$remote_addr \$request_method \$uri \$status \$body_bytes_sent \$request_time';

server {
    listen $GW_IP:$PROXY_PORT;
    server_name _;
    access_log $LOG_DIR/credproxy.log agentlab;
    resolver 127.0.0.53 valid=300s ipv6=off;
    client_max_body_size 64m;
    include $TOKEN_FILE;

    location = /v1/messages              { limit_except POST { deny all; } include /etc/nginx/agentlab-upstream.conf; }
    location = /v1/messages/count_tokens { limit_except POST { deny all; } include /etc/nginx/agentlab-upstream.conf; }
    # Add more exact paths here only if they are model calls (see credproxy.log 403s).

    location / { return 403; }
}
EOF
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/agentlab /etc/nginx/sites-enabled/agentlab
nginx -t -q
systemctl enable -q nginx
systemctl restart nginx

# ---------------------------------------------------------------- SSH
say "SSH"
install -d -m 700 -o "$OPERATOR" -g "$OPERATOR" "$OPERATOR_HOME/.ssh"
KEY="$OPERATOR_HOME/.ssh/agentlab_ed25519"
if [[ ! -f "$KEY" ]]; then
  sudo -u "$OPERATOR" ssh-keygen -q -t ed25519 -N "" -C "agentlab-gw run key" -f "$KEY"
fi
if [[ -s "$OPERATOR_HOME/.ssh/authorized_keys" ]]; then
  cat > /etc/ssh/sshd_config.d/00-agentlab.conf <<'EOF'
# Written by gateway-setup.sh. Key-only logins.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
  sshd -t && { systemctl try-reload-or-restart ssh.service || true; }
  note "Password SSH logins are now off; your key in authorized_keys still works."
else
  note "No authorized_keys for $OPERATOR yet, so password SSH stays on for now."
  note "Add your Windows public key, then re-run this script to turn passwords off."
fi

# ---------------------------------------------------------------- tools
say "Installing agentlab commands"
install -m 0755 "$HERE/agentlab-run"         /usr/local/bin/agentlab-run
install -m 0755 "$HERE/agentlab-monitor.py"  /usr/local/bin/agentlab-monitor
install -m 0755 "$HERE/agentlab-scan.py"     /usr/local/bin/agentlab-scan
install -m 0755 "$HERE/agentlab-check.sh"    /usr/local/bin/agentlab-check
install -d -m 0755 /etc/agentlab
echo "gateway" > /etc/agentlab/role

say "Gateway ready"
note "Run the gateway checks:   sudo agentlab-check gateway"
note "Give this public key to sandbox-setup.sh when it asks:"
echo
cat "$KEY.pub"
echo
note "Reminder: 'nginx -T' prints the token. Redact it before sharing config output."
