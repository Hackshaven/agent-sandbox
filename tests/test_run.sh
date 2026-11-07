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

# The gateway side of the interactive watcher, as shipped: end_session,
# watch_session and stop_watch from agentlab-run, run against a fake ssh feed, a
# stop_remote that (like a sandbox that won't listen) stops nothing, and a stand-in
# for the operator's ssh -t session. A watcher that stops, or is lost while the
# session runs, must end that session from the gateway.
GATEWAY_WATCH="$(awk '/^SESSION_FLAG=/ { f = 1 } /^trap .*Interrupted/ { exit } f' "$RUN")"
check "the gateway watcher functions are found" grep -q '^end_session()' <<<"$GATEWAY_WATCH"
gateway_case() {   # gateway_case NAME: prints "<watch_exit> <ended|running> <stop reason or ->"
  local dir="$TMP/gw-$1" sess
  mkdir -p "$dir/bin"
  printf '#!/bin/sh\nexec python3 -I %s "$@"\n' "$REPO/linux/agentlab-monitor.py" > "$dir/bin/agentlab-monitor"
  chmod +x "$dir/bin/agentlab-monitor"
  bash -c 'exec -a "ssh -t agent@10.77.0.10 x; echo \$\$ >\"\$HOME/.agentlab-session.pid\"; $1" sleep 60' _ "$1" &
  sess=$!
  CASE="$1" SESS="$sess" RUN_DIR="$dir" PATH="$dir/bin:$PATH" GATEWAY_WATCH="$GATEWAY_WATCH" bash -c '
    SBX=10.77.0.10; SSH_OPTS=(); WATCH_REMOTE=unused
    eval "$GATEWAY_WATCH"
    prompt() { printf "{\"type\": \"user\", \"permissionMode\": \"%s\", \"message\": {\"content\": \"hi\"}}\n" "$1"; }
    ssh() {   # the feed: what the sandbox side would send
      prompt auto
      case "$CASE" in
        stops) prompt plan; sleep 30 ;;
        lost) ;;
        normal) while kill -0 "$SESS" 2>/dev/null; do sleep 0.2; done ;;
      esac
    }
    stop_remote() { echo stop_remote >> "$RUN_DIR/calls"; }
    : > "$SESSION_FLAG"
    ( while kill -0 "$SESS" 2>/dev/null; do sleep 0.2; done; rm -f "$SESSION_FLAG" ) &
    watch_session & watch_pid=$!
    [ "$CASE" = normal ] && { sleep 1; kill "$SESS"; }
    for _ in $(seq 1 60); do kill -0 "$SESS" 2>/dev/null || break; sleep 0.25; done
    stop_watch' >/dev/null 2>&1
  local state=running
  kill -0 "$sess" 2>/dev/null || state=ended
  kill "$sess" 2>/dev/null; wait "$sess" 2>/dev/null
  printf '%s %s %s\n' "$(sed -n 's/^watch_exit=\([0-9]*\).*/\1/p' "$dir/meta.txt" | tail -1)" "$state" \
    "$(sed -n 's/^watch_stop=\(.*\) at=.*/\1/p' "$dir/meta.txt" | tail -1 | grep . || echo -)"
}
out="$(gateway_case stops)"
check "gateway: a monitor stop ends the session even if the sandbox ignores it [$out]" \
  grep -q '^3 ended the monitor stopped it' <<<"$out"
out="$(gateway_case lost)"
check "gateway: a watcher lost mid-session ends the session [$out]" \
  grep -q '^0 ended the watcher ended (exit 0) while the session ran' <<<"$out"
out="$(gateway_case normal)"
check "gateway: a session that ends by itself leaves no stop [$out]" test "$out" = "0 ended -"

if [[ $EUID -ne 0 ]]; then
  skip "not root: the session watcher and the preflight's route checks need namespaces (CI runs them with sudo)"
  finish; exit
fi

# The sandbox side of the interactive watcher, as shipped: the remote script
# agentlab-run sends over SSH, run here against a stand-in session (its PID in
# ~/.agentlab-session.pid, as the real launch writes it) and transcript files,
# piped into agentlab-monitor --session as agentlab-run does. Its own PID
# namespace keeps the tests' pkill away from anything else on this machine.
WATCH="$(awk "/^WATCH_REMOTE='/ { f = 1; sub(/^WATCH_REMOTE='/, \"\") } f { print } f && /'\$/ { exit }" "$RUN" \
  | sed "\$s/'\$//")"
check "the session watcher script is found" grep -q 'tail --pid' <<<"$WATCH"
if unshare --pid --fork --mount-proc true 2>/dev/null; then
  watch_case() {   # watch_case NAME: prints "<monitor exit> <early|held>"
    local home="$TMP/$1"
    mkdir -p "$home/bin" "$home/.claude/projects/-work-target"
    cp "$(command -v sleep)" "$home/bin/claude"
    WATCH="$WATCH" MONITOR="$REPO/linux/agentlab-monitor.py" CASE="$1" HOME="$home" \
      unshare --pid --fork --mount-proc bash -c '
        prompt() { printf "{\"type\": \"user\", \"permissionMode\": \"%s\", \"message\": {\"content\": \"hi\"}}\n" "$1"; }
        proj="$HOME/.claude/projects/-work-target"
        until_seen() { for _ in $(seq 1 40); do grep -q "$1" "$HOME/out.jsonl" 2>/dev/null && return 0; sleep 0.25; done; return 1; }
        until_done() { for _ in $(seq 1 "$1"); do [ -s "$HOME/rc" ] && return 0; sleep 0.25; done; return 1; }
        [ "$CASE" = stale ] && { prompt default > "$proj/old.jsonl"; sleep 1.1; }
        "$HOME/bin/claude" 120 & claude=$!
        echo "$claude" > "$HOME/.agentlab-session.pid"
        { bash -c "$WATCH" | python3 -I "$MONITOR" --session --quiet --out "$HOME/out.jsonl"
          echo "${PIPESTATUS[1]}" > "$HOME/rc"; } &
        sleep 1.2                      # transcripts must be newer than the watcher
        prompt auto >> "$proj/new.jsonl"
        until_seen "\"auto\"" || { echo "never-followed"; kill "$claude"; exit; }
        case "$CASE" in
          leaves) prompt acceptEdits >> "$proj/new.jsonl" ;;
          clear)  sleep 1.1; prompt plan >> "$proj/cleared.jsonl" ;;
          init)   echo "{\"type\": \"system\", \"subtype\": \"init\"}" >> "$proj/new.jsonl" ;;
          kill)   pkill -x tail ;;
          swap)   mv "$proj/new.jsonl" "$proj/new.bak"; ln -s /dev/null "$proj/new.jsonl" ;;
          stop)   pkill -STOP -x tail ;;
        esac
        until_done 16 && when=early || when=held
        kill "$claude"; pkill -CONT -x tail 2>/dev/null
        until_done 20
        echo "$(cat "$HOME/rc" 2>/dev/null || echo none) $when"'
  }
  check "watcher: a session that stays in auto mode is followed to its end" test "$(watch_case stays)" = "0 held"
  check "watcher: a prompt sent outside auto mode stops it" test "$(watch_case leaves)" = "3 early"
  check "watcher: a transcript from before the session is ignored" test "$(watch_case stale)" = "0 held"
  check "watcher: it follows the new transcript /clear starts" test "$(watch_case clear)" = "3 early"
  check "watcher: an init record written into the transcript stops it" test "$(watch_case init)" = "7 early"
  for c in kill swap stop; do
    out="$(watch_case "$c")"
    check "watcher: tampering ($c) ends the watcher while the session runs [$out]" grep -q ' early$' <<<"$out"
  done
  check "watcher: the gateway keeps a copy of what it followed" grep -q '"permissionMode": "auto"' "$TMP/stays/out.jsonl"
else
  skip "PID namespaces unavailable here; skipping the session watcher"
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
