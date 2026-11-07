#!/usr/bin/env bash
# Renders the gateway firewall from gateway-setup.sh, syntax-checks it, then (as
# root, where network namespaces work) builds a three-namespace copy of the lab
# (sandbox, gateway, and a stand-in for the internet beyond the gateway) and checks
# what can and can't get through. Every refusal has a control: the same path,
# shown open before the rules load, so a pass means the firewall stopped it.
set -uo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/lib.sh"

echo "firewall"
command -v nft >/dev/null || { skip "nft not installed"; exit 0; }
TMP="$(mktemp -d)"
GW=agentlab-test-gw SBX=agentlab-test-sbx NET=agentlab-test-net
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  for ns in "$GW" "$SBX" "$NET"; do ip netns del "$ns" 2>/dev/null; done
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
ip netns add "$SBX"; ip netns add "$NET"
G() { ip netns exec "$GW" "$@"; }
S() { ip netns exec "$SBX" "$@"; }
N() { ip netns exec "$NET" "$@"; }

# Lab link: gateway eth1 <-> sandbox eth0, IPv4 and (for the IPv6 drop) IPv6.
ip link add eth1 netns "$GW" type veth peer name eth0 netns "$SBX"
G ip link set lo up; S ip link set lo up; N ip link set lo up
G ip addr add 10.77.0.1/24 dev eth1; G ip link set eth1 up
S ip addr add 10.77.0.10/24 dev eth0; S ip link set eth0 up
V6=0   # some kernels (and sandboxes) have no IPv6; those cases skip there and run in CI
if G ip -6 addr add fd77::1/64 dev eth1 nodad 2>/dev/null && S ip -6 addr add fd77::10/64 dev eth0 nodad 2>/dev/null; then
  V6=1
fi
# Internet side: gateway wan0 <-> wan1 in a third namespace that routes the lab back.
ip link add wan0 netns "$GW" type veth peer name wan1 netns "$NET"
G ip addr add 192.0.2.1/24 dev wan0; G ip link set wan0 up
N ip addr add 192.0.2.2/24 dev wan1; N ip link set wan1 up
N ip route add 10.77.0.0/24 via 192.0.2.1
G sysctl -qw net.ipv4.ip_forward=0

listen() {   # listen NS ADDR PORT [udp|sink]: TCP accept-and-close, a UDP echo,
             # or a UDP sink that records each datagram in $TMP/sink (no reply)
  ip netns exec "$1" python3 -c '
import socket, sys
addr, port, proto, sink = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
if proto in ("udp", "sink"):
    s = socket.socket(fam, socket.SOCK_DGRAM); s.bind((addr, port))
    while True:
        data, peer = s.recvfrom(2048)
        if proto == "udp":
            s.sendto(data, peer)
        else:
            with open(sink, "ab") as f:
                f.write(data + b"\n")
s = socket.socket(fam); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port)); s.listen(16)
while True:
    c, _ = s.accept(); c.close()' "$2" "$3" "${4:-tcp}" "$TMP/sink" &
  PIDS+=($!)
}
listen "$GW" 10.77.0.1 8080          # the proxy
(( V6 )) && listen "$GW" fd77::1 8080   # the proxy port, over IPv6
listen "$GW" 0.0.0.0 22
listen "$GW" 0.0.0.0 2222
listen "$GW" 0.0.0.0 53 udp          # a resolver on the gateway
listen "$GW" 192.0.2.1 443           # the gateway's internet-side address
listen "$NET" 192.0.2.2 443          # a host on the internet
listen "$NET" 192.0.2.2 53 udp       # a resolver on the internet
listen "$SBX" 0.0.0.0 22
listen "$SBX" 0.0.0.0 80
listen "$SBX" 0.0.0.0 9999 sink      # records datagrams that reach the sandbox
sleep 1

tcp() {   # tcp NS HOST PORT [SRC]: succeeds if a TCP connection opens within 3s
  ip netns exec "$1" timeout 4 python3 -c '
import socket, sys
host, port, src = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
if src: s.bind((src, 0))
s.settimeout(3); s.connect((host, port))' "$2" "$3" "${4:-}" 2>/dev/null
}
udp() {   # udp NS HOST PORT: succeeds if a UDP echo comes back within 2s
  ip netns exec "$1" timeout 4 python3 -c '
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2); s.sendto(b"agentlab", (host, port))
assert s.recvfrom(64)[0] == b"agentlab"' "$2" "$3" 2>/dev/null
}
delivered() {   # delivered NS HOST PORT: send one datagram; succeeds if the sink got it
  local tag="probe-$RANDOM-$RANDOM"
  ip netns exec "$1" python3 -c '
import socket, sys
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(sys.argv[3].encode(), (sys.argv[1], int(sys.argv[2])))' \
    "$2" "$3" "$tag" 2>/dev/null
  sleep 0.5
  grep -qx "$tag" "$TMP/sink" 2>/dev/null
}
route_out()   { S ip route replace default via 10.77.0.1; }   # what an agent with root would add
no_route_out() { S ip route del default via 10.77.0.1 2>/dev/null; true; }
forwarding()  { G sysctl -qw "net.ipv4.ip_forward=$1"; }

# Controls: with no rules loaded, every path below is open. If one isn't, the
# matching refusal later proves nothing, so the test stops here.
controls_before="$T_FAIL"
check "control: gateway SSH (:22) is reachable" tcp "$SBX" 10.77.0.1 22
check "control: the gateway resolver (UDP 53) answers" udp "$SBX" 10.77.0.1 53
if (( V6 )); then check "control: the proxy port answers over IPv6" tcp "$SBX" fd77::1 8080
else skip "IPv6 isn't available here, so the IPv6 drop isn't tested"; fi
check "control: the proxy address answers from the internet side" tcp "$NET" 10.77.0.1 8080
route_out
check "control: with a route, the gateway's internet-side address is reachable" tcp "$SBX" 192.0.2.1 443
forwarding 1
check "control: with forwarding on, an internet host is reachable" tcp "$SBX" 192.0.2.2 443
check "control: with forwarding on, an internet resolver answers" udp "$SBX" 192.0.2.2 53
check "control: with forwarding on, a datagram from the internet reaches the sandbox" delivered "$NET" 10.77.0.10 9999
forwarding 0
no_route_out
if (( T_FAIL > controls_before )); then
  bad "a control failed, so the refusals below would prove nothing"; finish; exit
fi

check "rules load in a namespace" G nft -f "$TMP/nftables.conf"

# As built: forwarding off, no route out of the sandbox.
check  "sandbox reaches the proxy port (10.77.0.1:8080)" tcp "$SBX" 10.77.0.1 8080
refuse "sandbox can't reach gateway SSH (:22)" tcp "$SBX" 10.77.0.1 22
refuse "sandbox can't reach other gateway ports (:2222)" tcp "$SBX" 10.77.0.1 2222
refuse "sandbox can't use the gateway's resolver (UDP 53)" udp "$SBX" 10.77.0.1 53
(( V6 )) && refuse "sandbox can't reach the proxy port over IPv6" tcp "$SBX" fd77::1 8080
S ip addr add 10.77.0.20/24 dev eth0
refuse "proxy port refuses a different lab address (10.77.0.20)" tcp "$SBX" 10.77.0.1 8080 10.77.0.20
S ip addr del 10.77.0.20/24 dev eth0
refuse "proxy address doesn't answer on the internet side" tcp "$NET" 10.77.0.1 8080
check  "gateway can open SSH to the sandbox (:22)" tcp "$GW" 10.77.0.10 22
refuse "gateway can't open other sandbox ports (:80)" tcp "$GW" 10.77.0.10 80

# If the sandbox added a route out.
route_out
refuse "with a route, the gateway's internet-side address stays closed" tcp "$SBX" 192.0.2.1 443

# If forwarding were ever turned on, the rules still hold in both directions.
# Outbound, prerouting and the forward chain both drop the traffic, so taking out
# either one alone still passes; these check the boundary, not each rule.
forwarding 1
refuse "with forwarding on, an internet host stays unreachable" tcp "$SBX" 192.0.2.2 443
refuse "with forwarding on, an internet resolver stays unreachable" udp "$SBX" 192.0.2.2 53
# One way, so the sandbox's reply (which prerouting drops) plays no part: only
# the forward chain stands between this datagram and the sandbox.
refuse "with forwarding on, the forward chain stops a datagram from the internet" delivered "$NET" 10.77.0.10 9999
forwarding 0
no_route_out

listing="$(G nft list table inet agentlab)"
check "forward chain policy is drop" grep -q 'hook forward priority filter; policy drop' <<<"$listing"
check "denies are logged" grep -q 'log prefix "AGENTLAB-DENY: "' <<<"$listing"
finish
