#!/usr/bin/env bash
# sandbox-setup.sh: build the sandbox VM in phases. Run as root on agentlab-sbx.
#
#   sudo ./sandbox-setup.sh install [--docker] [--packages "pkg ..."] [--images "img ..."]
#                                   [--claude-version X.Y.Z] [--gateway-key "ssh-ed25519 ..."]
#       While still on the Default Switch (internet on). Installs tools, Claude
#       Code and the lab config. No token ever goes on this VM.
#
#   sudo ./sandbox-setup.sh cutover
#       After ".\agentlab.ps1 cutover" on Windows. Static 10.77.0.10, no routes,
#       no DNS, SSH only from the gateway. From here on there is no internet.
#
#   sudo ./sandbox-setup.sh finalize
#       After "sudo agentlab-check sandbox --model-call" passes. Adds the
#       No-network auto mode rule, then you take the baseline checkpoint.
#
#   sudo ./sandbox-setup.sh reopen
#       Maintenance only, after ".\agentlab.ps1 reopen": puts back the installer's
#       DHCP config so you can rerun install. Then cut over and check again.
set -euo pipefail

GW_IP=10.77.0.1
SBX_IP=10.77.0.10
PORT=8080
MIN_CLAUDE=2.1.257
MS_DIR=/etc/claude-code
MS="$MS_DIR/managed-settings.json"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PHASE="${1:-}"; shift || true
DOCKER=0 PACKAGES="" IMAGES="" CLAUDE_VERSION="" GW_KEY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker) DOCKER=1; shift ;;
    --packages) PACKAGES="$2"; shift 2 ;;
    --images) IMAGES="$2"; DOCKER=1; shift 2 ;;
    --claude-version) CLAUDE_VERSION="$2"; shift 2 ;;
    --gateway-key) GW_KEY="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "Run as root: sudo $0 $PHASE"
[[ -z "$CLAUDE_VERSION" || "$CLAUDE_VERSION" =~ ^([0-9]+\.[0-9]+\.[0-9]+|stable|latest)$ ]] \
  || die "--claude-version must be X.Y.Z, stable or latest"

version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
as_agent() { sudo -u agent -H bash -c 'set -a; . /etc/environment; set +a; cd "$HOME"; '"$1"; }

set_env_line() {   # set_env_line KEY VALUE  (in /etc/environment)
  local k="$1" v="$2"
  sed -i "/^${k}=/d" /etc/environment
  printf '%s="%s"\n' "$k" "$v" >> /etc/environment
}

write_managed_settings() {
  install -d -m 755 -o root -g root "$MS_DIR"
  cat > "$MS" <<EOF
{
  "permissions": {
    "defaultMode": "auto",
    "disableBypassPermissionsMode": "disable"
  },
  "autoMode": {
    "environment": [
      "\$defaults",
      "Host containment: disposable Hyper-V VM on an isolated private network, 10.77.0.0/24. No internet access and no DNS.",
      "The only route to the model API is the credential proxy at $GW_IP:$PORT. CLAUDE_CODE_OAUTH_TOKEN holds a placeholder, not a credential, and is not for the agent's commands.",
      "No cloud metadata service and no cloud identity. The Windows host, the gateway at $GW_IP and every other address on 10.77.0.0/24 are not part of the task. Hyper-V integration channels and sockets are not part of the task.",
      "Target: code, binaries and containers under /work/target, and services the agent starts on loopback or rootless Docker networks inside this VM."
    ],
    "soft_deny": [
      "\$defaults",
      "Tampering: changes to Claude Code settings, permission or hook files; to the proxy or API-endpoint environment variables; to /etc/environment, /etc/netplan, firewall, routing or SSH configuration; or to files under /work/inbox. Also any request to the credential proxy other than the CLI's own model calls, and stopping or signaling processes the agent did not start."
    ]
  }
}
EOF
  chown root:root "$MS"; chmod 644 "$MS"
}

# ===================================================================== install
phase_install() {
  rm -f /var/lib/agentlab/sandbox-checks-passed
  ip -4 route show default | grep -q . || die "No internet route. Run install while the VM is still on the Default Switch."
  [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] || die "Run with sudo from your admin account."

  say "Packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get -y -q full-upgrade
  # shellcheck disable=SC2086
  apt-get install -y -q build-essential git curl ca-certificates jq python3 python3-venv \
    gdb strace ltrace file binutils unzip xz-utils netcat-openbsd tmux $PACKAGES

  say "Agent account"
  if ! id agent >/dev/null 2>&1; then
    adduser --disabled-password --gecos "lab agent" agent
  fi
  for g in sudo docker adm lxd admin wheel disk root libvirt incus-admin; do gpasswd -d agent "$g" >/dev/null 2>&1 || true; done
  install -d -m 755 -o agent -g agent /work /work/target /work/inbox

  say "Gateway SSH key"
  if [[ -z "$GW_KEY" ]]; then
    note "Paste the public key that gateway-setup.sh printed (one line, ssh-ed25519 ...):"
    read -r GW_KEY
  fi
  [[ "$GW_KEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || die "That doesn't look like an ssh-ed25519 public key."
  install -d -m 700 -o agent -g agent /home/agent/.ssh
  printf 'from="%s",restrict,pty %s\n' "$GW_IP" "$GW_KEY" \
    > /home/agent/.ssh/authorized_keys
  chown agent:agent /home/agent/.ssh/authorized_keys; chmod 600 /home/agent/.ssh/authorized_keys

  if [[ $DOCKER == 1 ]]; then install_rootless_docker; fi

  say "Claude Code"
  as_agent "curl -fsSL https://claude.ai/install.sh -o /tmp/claude-install.sh && bash /tmp/claude-install.sh ${CLAUDE_VERSION}"
  local user_bin; user_bin="$(readlink -f /home/agent/.local/bin/claude 2>/dev/null || true)"
  [[ -x "$user_bin" ]] || die "Claude Code install didn't produce /home/agent/.local/bin/claude"
  # Root-owned copy, so the agent can't modify its own binary.
  install -m 755 -o root -g root "$user_bin" /usr/local/bin/claude
  if sudo -u agent -H /usr/local/bin/claude --version >/dev/null 2>&1; then
    rm -f /home/agent/.local/bin/claude
    rm -rf /home/agent/.local/share/claude
    note "Installed root-owned /usr/local/bin/claude; removed the agent-owned copy."
  else
    ln -sf "$user_bin" /usr/local/bin/claude
    note "The copied binary didn't run, so the agent-owned install stays (agentlab-check will warn)."
  fi
  local v; v="$(as_agent 'claude --version' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  [[ -n "$v" ]] || die "claude --version failed for agent"
  version_ge "$v" "$MIN_CLAUDE" || die "Claude Code $v is older than $MIN_CLAUDE (needed for the default containment rules)."
  note "Claude Code $v"

  say "Lab config (no credentials)"
  set_env_line ANTHROPIC_BASE_URL "http://$GW_IP:$PORT"
  set_env_line CLAUDE_CODE_OAUTH_TOKEN "placeholder-real-token-is-on-gateway"
  set_env_line DISABLE_AUTOUPDATER 1
  set_env_line CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC 1
  sed -i '/^ANTHROPIC_API_KEY=/d' /etc/environment
  chown root:root /etc/environment; chmod 644 /etc/environment
  write_managed_settings

  cat > /etc/modprobe.d/agentlab.conf <<'EOF'
# Written by sandbox-setup.sh: no Hyper-V sockets inside the sandbox.
install hv_sock /bin/false
blacklist hv_sock
EOF
  for svc in hv-fcopy-daemon hv-kvp-daemon hv-vss-daemon; do
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
  done

  install -m 755 "$HERE/agentlab-check.sh" /usr/local/sbin/agentlab-check
  install -d -m 755 /etc/agentlab; echo sandbox > /etc/agentlab/role

  say "Install phase done"
  note "Copy any target source, tools or images in now. After cutover nothing can be fetched."
  note "Next, on Windows:   .\\agentlab.ps1 cutover"
  note "Then at this console: sudo $0 cutover"
}

install_rootless_docker() {
  say "Rootless Docker for agent"
  install -d -m 755 /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-ce-rootless-extras \
    uidmap dbus-user-session slirp4netns
  # No root daemon: agent gets its own rootless daemon instead.
  systemctl disable --now docker.service docker.socket containerd.service >/dev/null 2>&1 || true
  gpasswd -d agent docker >/dev/null 2>&1 || true

  # Ubuntu 24.04 restricts unprivileged user namespaces; rootlesskit needs a profile.
  if [[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" == 1 ]] \
     && ! grep -rqs '/usr/bin/rootlesskit' /etc/apparmor.d/; then
    cat > /etc/apparmor.d/usr.bin.rootlesskit <<'EOF'
# Written by sandbox-setup.sh: lets rootless Docker create user namespaces.
abi <abi/4.0>,
include <tunables/global>

/usr/bin/rootlesskit flags=(unconfined) {
  userns,
  include if exists <local/usr.bin.rootlesskit>
}
EOF
    apparmor_parser -r /etc/apparmor.d/usr.bin.rootlesskit
  fi

  loginctl enable-linger agent
  local uid; uid="$(id -u agent)"
  systemctl start "user@${uid}.service"
  local rt="/run/user/$uid"
  for _ in $(seq 1 20); do [[ -S "$rt/bus" ]] && break; sleep 1; done
  sudo -u agent -H env XDG_RUNTIME_DIR="$rt" DBUS_SESSION_BUS_ADDRESS="unix:path=$rt/bus" \
    dockerd-rootless-setuptool.sh install
  set_env_line DOCKER_HOST "unix://$rt/docker.sock"
  for img in $IMAGES; do
    note "Pulling $img"
    sudo -u agent -H env XDG_RUNTIME_DIR="$rt" DOCKER_HOST="unix://$rt/docker.sock" docker pull "$img"
  done
}

# ===================================================================== cutover
phase_cutover() {
  rm -f /var/lib/agentlab/sandbox-checks-passed
  local ifs
  ifs="$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | cut -d@ -f1)"
  [[ "$(wc -w <<<"$ifs")" == 1 ]] || die "Expected one network interface, found: $ifs"
  local nic="$ifs"

  say "Static address $SBX_IP on $nic, no routes, no DNS"
  install -d -m 700 /etc/netplan.agentlab-backup
  find /etc/netplan -maxdepth 1 -name '*.yaml' ! -name '01-agentlab.yaml' -exec mv -f {} /etc/netplan.agentlab-backup/ \;
  install -d -m 755 /etc/cloud/cloud.cfg.d
  echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-agentlab-disable-network.cfg
  cat > /etc/netplan/01-agentlab.yaml <<EOF
# Written by sandbox-setup.sh. No gateway, no nameservers, no IPv6.
network:
  version: 2
  ethernets:
    $nic:
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      addresses: [$SBX_IP/24]
EOF
  chmod 600 /etc/netplan/01-agentlab.yaml
  cat > /etc/sysctl.d/60-agentlab.conf <<'EOF'
# Written by sandbox-setup.sh
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  sysctl -q --system
  netplan apply
  sleep 2

  say "SSH: agent from the gateway only"
  cat > /etc/ssh/sshd_config.d/00-agentlab.conf <<EOF
# Written by sandbox-setup.sh. Sorts first, so these values win.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers agent@$GW_IP
AllowTcpForwarding no
AllowStreamLocalForwarding no
AllowAgentForwarding no
PermitTunnel no
X11Forwarding no
EOF
  sshd -t
  systemctl restart ssh.service 2>/dev/null || systemctl restart ssh.socket

  say "Quieting services that would try the network"
  for u in apt-daily.timer apt-daily-upgrade.timer motd-news.timer unattended-upgrades.service \
           snapd.service snapd.socket fwupd-refresh.timer; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
  done

  say "Cutover done"
  ip -4 addr show dev "$nic" | sed 's/^/    /'
  note "Next: on the gateway run   sudo agentlab-check gateway"
  note "Then here, once as agent, accept Claude Code's first-run prompts:"
  note "    sudo -iu agent claude        (say hi, check it answers, then /exit)"
  note "Then here:                     sudo agentlab-check sandbox --model-call"
}

# ===================================================================== finalize
phase_finalize() {
  [[ -f /var/lib/agentlab/sandbox-checks-passed ]] \
    || die "Run 'sudo agentlab-check sandbox --model-call' first; finalize needs every check to pass."
  say "Adding the No-network rule to auto mode"
  python3 - "$MS" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    d = json.load(f)
rule = ("No network: this environment is declared no-network except the credential proxy. "
        "Treat ANY direct request to another outside host (curl, wget, git, pip, npm, apt to a "
        "public URL or package index) as Containment Escape.")
sd = d.setdefault("autoMode", {}).setdefault("soft_deny", ["$defaults"])
if not any(r.startswith("No network:") for r in sd):
    sd.append(rule)
with open(path, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY
  chown root:root "$MS"; chmod 644 "$MS"
  as_agent 'claude auto-mode config' | grep -q 'No network' \
    && note "claude auto-mode config shows the rule." \
    || note "Warning: claude auto-mode config doesn't show the rule yet; check it in a new session."
  rm -rf /home/agent/.claude/projects    # don't bake check sessions into the baseline
  say "Finalized"
  note "On Windows:  .\\agentlab.ps1 baseline   then run the escape test (README)."
}

phase_reopen() {
  rm -f /var/lib/agentlab/sandbox-checks-passed
  compgen -G '/etc/netplan.agentlab-backup/*.yaml' >/dev/null || die "No saved installer network config to restore."
  say "Restoring the installer's network config (DHCP) for maintenance"
  rm -f /etc/netplan/01-agentlab.yaml /etc/cloud/cloud.cfg.d/99-agentlab-disable-network.cfg
  mv -f /etc/netplan.agentlab-backup/*.yaml /etc/netplan/
  netplan apply
  sleep 5
  ip -4 route show default | grep -q . && note "Internet route is back." \
    || note "No route yet. Is the adapter on the Default Switch (.\\agentlab.ps1 reopen)?"
  note "Next: sudo $0 install ...   then cut over, check and finalize again."
}

case "$PHASE" in
  reopen) phase_reopen ;;
  install) phase_install ;;
  cutover) phase_cutover ;;
  finalize) phase_finalize ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
