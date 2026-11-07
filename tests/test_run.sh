#!/usr/bin/env bash
# Runs agentlab-run's launch checks with no lab: the limits and the task file are
# checked before anything connects, so each case either names its refusal or
# reaches the next check (no run key in an empty HOME). Then runs lines from the
# sandbox preflight it sends over SSH: the group check here, and (as root, in a
# network namespace) the route and IPv6 checks.
set -uo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/lib.sh"

echo "run launcher"
RUN="$REPO/linux/agentlab-run"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
printf '## Scope\n- test\n\n## Task\nnothing\n' > "$TMP/task.md"
printf '## Task\nno scope section\n' > "$TMP/noscope.md"

refusal() {   # refusal ARGS...: agentlab-run's first line on stderr
  HOME="$TMP" bash "$RUN" "$@" 2>&1 >/dev/null | head -1
}
refused_for() {   # refused_for TEXT ARGS...: passes when the refusal contains TEXT
  local want="$1"; shift
  [[ "$(refusal "$@")" == *"$want"* ]]
}
# A case that passes every limit check stops at the next one: no run key in $TMP.
gets_past_limits() { refused_for "No run key" "$@"; }

check "a valid task with default limits reaches the run-key check" gets_past_limits --task "$TMP/task.md"
for t in 0 0s 0m 0h 00 05m "" -1 2d 1.5h 30M; do
  check "--time '$t' is refused" refused_for "--time must be" --task "$TMP/task.md" --time "$t"
done
for t in 1 30m 2h 5400s 5400; do
  check "--time '$t' is accepted" gets_past_limits --task "$TMP/task.md" --time "$t"
done
for n in 0 501 x ""; do
  check "--turns '$n' is refused" refused_for "--turns must be" --task "$TMP/task.md" --turns "$n"
done
check "a task file without '## Scope' is refused" refused_for "no '## Scope' section" --task "$TMP/noscope.md"
check "a missing task file is refused" refused_for "--task file not found" --task "$TMP/missing.md"

# The sandbox preflight, as shipped: the heredoc agentlab-run sends over SSH.
PREFLIGHT="$(heredoc_body "<<'REMOTE'" "$RUN" REMOTE)"
NET_CHECKS="$(grep -E '^ip -[46] ' <<<"$PREFLIGHT")"
GROUP_CHECK="$(grep -E '^id -nG ' <<<"$PREFLIGHT")"
check "the preflight has one route check and one IPv6 check" test "$(grep -c . <<<"$NET_CHECKS")" -eq 2
check "the preflight has one group check" test "$(grep -c . <<<"$GROUP_CHECK")" -eq 1

group_flagged() {   # group_flagged "GROUPS": the group check, for a user in GROUPS
  [[ -n "$(FAKE_GROUPS="$1" bash -c 'id() { echo "$FAKE_GROUPS"; }; '"$GROUP_CHECK" 2>/dev/null)" ]]
}
for g in sudo admin wheel docker adm lxd; do
  check "the preflight refuses an agent in $g" group_flagged "agent $g"
done
refuse "the preflight accepts an agent in no privileged group" group_flagged "agent users sudoers dockerx"

# The three places that list the privileged groups have to agree.
words() { tr -c 'a-z\n' ' ' | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' '; }
quoted_alternation() { grep -oE "grep -qwE '[a-z|]+'" "$1" | head -1 | sed -E "s/.*'(.*)'/\1/" | words; }
run_groups="$(quoted_alternation "$RUN")"
check_groups="$(quoted_alternation "$REPO/linux/agentlab-check.sh")"
setup_groups="$(grep -oE 'for g in [a-z ]+; do gpasswd' "$REPO/linux/sandbox-setup.sh" \
  | sed -E 's/for g in (.*); do gpasswd/\1/' | words)"
check "the preflight lists privileged groups" test -n "$run_groups"
check "agentlab-check checks the preflight's groups [$run_groups]" test "$check_groups" = "$run_groups"
check "sandbox-setup removes the preflight's groups [$run_groups]" test "$setup_groups" = "$run_groups"

if [[ $EUID -ne 0 ]]; then
  skip "not root: the preflight's route checks run in a network namespace (CI runs them with sudo)"
  finish; exit
fi
NS=agentlab-test-preflight
if ! ip netns add "$NS" 2>/dev/null; then
  skip "network namespaces unavailable here; skipping the preflight's route checks"
  finish; exit
fi
trap 'ip netns del "$NS" 2>/dev/null; rm -rf "$TMP"' EXIT
X() { ip netns exec "$NS" "$@"; }
# Like the sandbox after cutover: IPv6 off, one address on the lab subnet.
X sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
X ip link set lo up
X ip link add eth0 type veth peer name eth0p
X ip addr add 10.77.0.10/24 dev eth0; X ip link set eth0p up; X ip link set eth0 up
net_problems() { X bash -c "$NET_CHECKS" 2>/dev/null; }

check "a sandbox with only the lab subnet passes" test -z "$(net_problems)"
X ip route add 192.0.2.0/24 via 10.77.0.1
check "a route to one outside network is refused" grep -q "route beyond" <<<"$(net_problems)"
X ip route del 192.0.2.0/24 via 10.77.0.1
X ip route add default via 10.77.0.1
check "a default route is refused" grep -q "route beyond" <<<"$(net_problems)"
X ip route del default via 10.77.0.1
if X sysctl -qw net.ipv6.conf.eth0.disable_ipv6=0 2>/dev/null && X ip -6 addr add fd77::10/64 dev eth0 nodad 2>/dev/null; then
  check "an IPv6 address is refused" grep -q "IPv6 address" <<<"$(net_problems)"
else
  skip "IPv6 isn't available here, so the preflight's IPv6 check isn't tested"
fi
finish
