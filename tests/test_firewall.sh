#!/usr/bin/env bash
# Renders the gateway firewall from gateway-setup.sh, syntax-checks it, then (as
# root, where network namespaces work) builds a two-namespace copy of the lab and
# checks what the sandbox can and can't reach.
set -uo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/lib.sh"

echo "firewall"
command -v nft >/dev/null || { skip "nft not installed"; exit 0; }
TMP="$(mktemp -d)"
GW=agentlab-test-gw SBX=agentlab-test-sbx
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  ip netns del "$GW" 2>/dev/null; ip netns del "$SBX" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

render_heredoc 'cat > /etc/nftables.conf <<EOF' \
  'GW_IP=10.77.0.1 SBX_IP=10.77.0.10 PROXY_PORT=8080 INSIDE_IF=eth1 RATE="limit rate 50/second burst 200 packets"' \
  > "$TMP/nftables.conf" || { bad "render nftables.conf"; finish; exit; }

if [[ $EUID -ne 0 ]]; then
  skip "not root: syntax check and namespace tests need root (CI runs them with sudo)"
  finish; exit
fi

check "nftables.conf passes nft -c" nft -c -f "$TMP/nftables.conf"

if ! ip netns add "$GW" 2>/dev/null; then
  skip "network namespaces unavailable here; skipping the reachability tests"
  finish; exit
fi
ip netns add "$SBX"
G() { ip netns exec "$GW" "$@"; }
S() { ip netns exec "$SBX" "$@"; }

# Lab link: gateway eth1 <-> sandbox eth0.
ip link add eth1 netns "$GW" type veth peer name eth0 netns "$SBX"
G ip link set lo up; S ip link set lo up
G ip addr add 10.77.0.1/24 dev eth1; G ip link set eth1 up
S ip addr add 10.77.0.10/24 dev eth0; S ip link set eth0 up
# Stand-in for the gateway's internet-facing side: a second veth inside the gateway.
G ip link add wan0 type veth peer name wan1
G ip addr add 192.0.2.1/24 dev wan0; G ip link set wan0 up; G ip link set wan1 up
G sysctl -qw net.ipv4.ip_forward=0

listen() {   # listen NS ADDR PORT : accept-and-close TCP listener
  ip netns exec "$1" python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16)
while True:
    c, _ = s.accept(); c.close()' "$2" "$3" &
  PIDS+=($!)
}
listen "$GW" 10.77.0.1 8080
listen "$GW" 0.0.0.0 22
listen "$GW" 0.0.0.0 2222
listen "$GW" 192.0.2.1 443
listen "$SBX" 0.0.0.0 22
listen "$SBX" 0.0.0.0 80
sleep 1

tcp() {   # tcp NS HOST PORT [SRC]: succeeds if a TCP connection opens within 3s
  local ns="$1" host="$2" port="$3" src="${4:-}"
  ip netns exec "$ns" timeout 3 python3 -c '
import socket, sys
s = socket.socket()
if len(sys.argv) > 3 and sys.argv[3]: s.bind((sys.argv[3], 0))
s.settimeout(2.5); s.connect((sys.argv[1], int(sys.argv[2])))' "$host" "$port" "$src" 2>/dev/null
}

# Controls: with no firewall, these succeed. If they don't, the tests below prove nothing.
S ip route add default via 10.77.0.1
check "control: without rules, gateway SSH is reachable" tcp "$SBX" 10.77.0.1 22
check "control: without rules, the gateway's other address is reachable" tcp "$SBX" 192.0.2.1 443
S ip route del default via 10.77.0.1

check "rules load in a namespace" G nft -f "$TMP/nftables.conf"
check  "sandbox reaches the proxy port (10.77.0.1:8080)" tcp "$SBX" 10.77.0.1 8080
refuse "sandbox can't reach gateway SSH (:22)" tcp "$SBX" 10.77.0.1 22
refuse "sandbox can't reach other gateway ports (:2222)" tcp "$SBX" 10.77.0.1 2222
refuse "sandbox can't reach the gateway's other address (192.0.2.1)" tcp "$SBX" 192.0.2.1 443
S ip route add default via 10.77.0.1
refuse "gateway won't route for the sandbox, even with a default route" tcp "$SBX" 192.0.2.1 443
S ip route del default via 10.77.0.1
S ip addr add 10.77.0.20/24 dev eth0
refuse "proxy port refuses a different lab address (10.77.0.20)" tcp "$SBX" 10.77.0.1 8080 10.77.0.20
check  "gateway can open SSH to the sandbox (:22)" tcp "$GW" 10.77.0.10 22
refuse "gateway can't open other sandbox ports (:80)" tcp "$GW" 10.77.0.10 80

listing="$(G nft list table inet agentlab)"
check "forward chain policy is drop" grep -q 'hook forward priority filter; policy drop' <<<"$listing"
check "denies are logged" grep -q 'log prefix "AGENTLAB-DENY: "' <<<"$listing"
finish
