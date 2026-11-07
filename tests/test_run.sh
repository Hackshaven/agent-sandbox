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
for t in 0 0s 0m 0h 00 05m "" -1 2d 1.5h 30M 25h 1441m 86401s 86401 1234567h; do
  check "--time '$t' is refused" refused_for "--time must be" --task "$TMP/task.md" --time "$t"
done
for t in 1 30m 2h 5400s 5400 24h 1440m 86400; do
  check "--time '$t' is accepted" gets_past_limits --task "$TMP/task.md" --time "$t"
done
for n in 0 501 x ""; do
  check "--turns '$n' is refused" refused_for "--turns must be" --task "$TMP/task.md" --turns "$n"
done
check "a task file without '## Scope' is refused" refused_for "no '## Scope' section" --task "$TMP/noscope.md"
check "a missing task file is refused" refused_for "--task file not found" --task "$TMP/missing.md"

# Whatever the sandbox writes on stderr reaches the operator's terminal through
# sbx, so sbx must show it through cat -v.
SBX_FN="$(grep -E '^sbx\(\) ' "$RUN")"
mkdir -p "$TMP/fakessh"
printf '#!/bin/sh\nprintf "\\033]0;owned\\007boom\\n" >&2\n' > "$TMP/fakessh/ssh"; chmod +x "$TMP/fakessh/ssh"
# shellcheck disable=SC2034  # SSH_OPTS and SBX are read by the eval'd sbx
stderr_seen="$(PATH="$TMP/fakessh:$PATH"; SSH_OPTS=(); SBX=x; eval "$SBX_FN"; sbx 5 true 2>&1)"
check "sbx shows the sandbox's stderr with control characters visible" \
  bash -c '[[ "$1" != *$'"'"'\e'"'"'* && "$1" == *"^["*boom* ]]' _ "$stderr_seen"

# The sandbox preflight, as shipped: the heredoc agentlab-run sends over SSH.
PREFLIGHT="$(heredoc_body "<<'REMOTE'" "$RUN" REMOTE)"
NET_CHECKS="$(grep -E '^(ip |\[ "\$\(ip )' <<<"$PREFLIGHT")"
GROUP_CHECK="$(grep -E '^id -nG ' <<<"$PREFLIGHT")"
SUDO_CHECK="$(grep -E '^sudo -n ' <<<"$PREFLIGHT")"
check "the preflight has its five network checks" test "$(grep -c . <<<"$NET_CHECKS")" -eq 5
check "the preflight has one group check" test "$(grep -c . <<<"$GROUP_CHECK")" -eq 1
check "the preflight has one sudo check" test "$(grep -c . <<<"$SUDO_CHECK")" -eq 1
sudo_flagged() { [[ -n "$(SUDO_RC="$1" bash -c 'sudo() { return "$SUDO_RC"; }; '"$SUDO_CHECK" 2>/dev/null)" ]]; }
check "the preflight refuses password-less sudo" sudo_flagged 0
refuse "the preflight accepts an agent sudo refuses" sudo_flagged 1

group_flagged() {   # group_flagged "GROUPS": the group check, for a user in GROUPS
  [[ -n "$(FAKE_GROUPS="$1" bash -c 'id() { echo "$FAKE_GROUPS"; }; '"$GROUP_CHECK" 2>/dev/null)" ]]
}
for g in sudo admin wheel docker adm lxd disk root libvirt incus-admin; do
  check "the preflight refuses an agent in $g" group_flagged "agent $g"
done
refuse "the preflight accepts an agent in no privileged group" group_flagged "agent users sudoers dockerx"

# The three places that list the privileged groups have to agree.
words() { tr -c 'a-z\n-' ' ' | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' '; }
quoted_alternation() { grep -oE "grep -qwE '[a-z|-]+'" "$1" | head -1 | sed -E "s/.*'(.*)'/\1/" | words; }
run_groups="$(quoted_alternation "$RUN")"
check_groups="$(quoted_alternation "$REPO/linux/agentlab-check.sh")"
setup_groups="$(grep -oE 'for g in [a-z -]+; do gpasswd' "$REPO/linux/sandbox-setup.sh" \
  | sed -E 's/for g in (.*); do gpasswd/\1/' | words)"
check "the preflight lists privileged groups" test -n "$run_groups"
check "agentlab-check checks the preflight's groups [$run_groups]" test "$check_groups" = "$run_groups"
check "sandbox-setup removes the preflight's groups [$run_groups]" test "$setup_groups" = "$run_groups"

# The gateway side of the interactive watcher, as shipped: end_session,
# watch_session and stop_watch from agentlab-run, run against a fake ssh feed, a
# stop_remote that (like a sandbox that won't listen) stops nothing, and a stand-in
# for the operator's ssh -t session. A watcher that stops, or is lost while the
# session runs, must end that session from the gateway.
GATEWAY_WATCH="$(awk '/^SESSION_FLAG=/ { f = 1 } /^on_signal\(\)/ { exit } f' "$RUN")"
check "the gateway watcher functions are found" grep -q '^end_session()' <<<"$GATEWAY_WATCH"
# The stand-in session carries the command line agentlab-run launches, so the
# pattern end_session kills by is checked against the real thing.
LAUNCH_LINE="$(grep -oE '"timeout --foreground -k 30 .*permission-mode auto'"'"'"' "$RUN")"
SESSION_CMD="$(bash -c 'SSH_OPTS=(-i key -o BatchMode=yes); SBX=10.77.0.10; REMOTE_ENV="cd /work/target"
  time_s=60; TIME=1m; MODEL=claude-x; eval "cmd=$1"; printf %s "$cmd"' _ "$LAUNCH_LINE")"
check "the interactive launch line is found" grep -q -- '-t agent@10.77.0.10 .*agentlab-session.pid' <<<"$SESSION_CMD"
gateway_case() {   # gateway_case NAME: prints "<watch_exit> <ended|running> <stop_remote calls> <feed gone|left> <unfinished yes|no> <stop reason or ->"
  local dir="$TMP/gw-$1" sess feed
  mkdir -p "$dir/bin"
  printf '#!/bin/sh\nexec python3 -I %s "$@"\n' "$REPO/linux/agentlab-monitor.py" > "$dir/bin/agentlab-monitor"
  # The feed: what the sandbox side would send. A script, since timeout runs it.
  cat > "$dir/bin/ssh" <<'FEED'
#!/bin/bash
echo $$ > "$RUN_DIR/feed-ssh.pid"
prompt() { printf '{"type": "user", "permissionMode": "%s", "message": {"content": "hi"}}\n' "$1"; }
beat() { printf '{"agentlab": "heartbeat"}\n'; }
prompt auto
case "$CASE" in
  stops|hang) prompt plan; sleep 30 ;;
  lost) ;;
  normal) while kill -0 "$SESS" 2>/dev/null; do beat; sleep 0.2; done ;;
  quiet) sleep 30 ;;                                   # connected, but silent
  wedge) while :; do beat; sleep 0.2; done ;;          # still beating after the session
  cut) printf '{"type": "user", "message": {"content": "'
       while :; do printf x; sleep 0.1; done ;;        # a record that never finishes
esac
FEED
  chmod +x "$dir/bin/agentlab-monitor" "$dir/bin/ssh"
  bash -c 'exec -a "$1" sleep 60' _ "$SESSION_CMD" &
  sess=$!
  CASE="$1" SESS="$sess" RUN_DIR="$dir" PATH="$dir/bin:$PATH" GATEWAY_WATCH="$GATEWAY_WATCH" bash -c '
    export CASE SESS RUN_DIR
    SBX=10.77.0.10; SSH_OPTS=(); WATCH_REMOTE=unused; time_s=60
    eval "$GATEWAY_WATCH"
    WATCH_STALL=2 WATCH_GRACE=3
    stop_remote() { echo stop_remote >> "$RUN_DIR/calls"; [ "$CASE" = hang ] && sleep 30; true; }
    : > "$SESSION_FLAG"
    ( while kill -0 "$SESS" 2>/dev/null; do sleep 0.2; done; rm -f "$SESSION_FLAG" ) &
    watch_session & watch_pid=$!
    case "$CASE" in normal|wedge) sleep 1; kill "$SESS" ;; cut) sleep 0.3; kill "$SESS" ;; esac
    for _ in $(seq 1 60); do kill -0 "$SESS" 2>/dev/null || break; sleep 0.25; done
    stop_watch' >/dev/null 2>&1
  local state=running
  kill -0 "$sess" 2>/dev/null || state=ended
  kill "$sess" 2>/dev/null; wait "$sess" 2>/dev/null
  feed=gone
  [[ -s "$dir/feed-ssh.pid" ]] && kill -0 "$(cat "$dir/feed-ssh.pid")" 2>/dev/null && feed=left
  printf '%s %s %s %s %s %s\n' "$(sed -n 's/^watch_exit=\([0-9]*\).*/\1/p' "$dir/meta.txt" | tail -1)" "$state" \
    "$(grep -c stop_remote "$dir/calls" 2>/dev/null || echo 0)" "$feed" \
    "$(grep -q '^watch_unfinished=' "$dir/meta.txt" && echo yes || echo no)" \
    "$(sed -n 's/^watch_stop=\(.*\) at=.*/\1/p' "$dir/meta.txt" | tail -1 | grep . || echo -)"
}
out="$(gateway_case stops)"
check "gateway: a monitor stop ends the session even if the sandbox ignores it [$out]" \
  grep -q '^3 ended 1 gone no the monitor stopped it' <<<"$out"
out="$(gateway_case hang)"
check "gateway: it ends the session even while stop_remote hangs [$out]" \
  grep -q '^3 ended 1 gone no the monitor stopped it' <<<"$out"
out="$(gateway_case lost)"
check "gateway: a watcher lost mid-session ends the session [$out]" \
  grep -q '^0 ended 1 gone no the watcher ended (exit 0) while the session ran' <<<"$out"
out="$(gateway_case quiet)"
check "gateway: a watcher that goes quiet but stays connected ends the session [$out]" \
  grep -q '^8 ended 1 gone no the monitor stopped it (exit 8)' <<<"$out"
out="$(gateway_case wedge)"
check "gateway: a feed still running after the session is ended and flagged [$out]" \
  test "$out" = "0 ended 0 gone yes -"
out="$(gateway_case cut)"
check "gateway: a monitor stop after the session ended doesn't claim to end it [$out]" \
  test "$out" = "8 ended 0 gone no -"
out="$(gateway_case normal)"
check "gateway: a session that ends by itself leaves no stop [$out]" test "$out" = "0 ended 0 gone no -"

if [[ $EUID -ne 0 ]]; then
  skip "not root: the session watcher and the preflight's route checks need namespaces (CI runs them with sudo)"
  finish; exit
fi

# The sandbox side of the interactive watcher, as shipped: the Python script
# agentlab-run sends on ssh's stdin, run here against a stand-in session (its PID
# in ~/.agentlab-session.pid, as the real launch writes it) and transcript files,
# piped into agentlab-monitor --session as agentlab-run does. Its own PID
# namespace keeps the tests' pkill away from anything else on this machine.
WATCH="$(heredoc_body "<<'WATCH'" "$RUN" WATCH)"
check "the session watcher script is found" grep -q 'HEARTBEAT' <<<"$WATCH"
# Two values the watcher and agentlab-monitor must agree on, written in both.
same_value() {   # same_value REGEX: the first match in the watcher and in the monitor agree
  local a b
  a="$(grep -oE "$1" <<<"$WATCH" | head -1)"; b="$(grep -oE "$1" "$REPO/linux/agentlab-monitor.py" | head -1)"
  [[ -n "$a" && "$a" == "$b" ]]
}
check "the watcher and the monitor agree on the heartbeat" same_value "^HEARTBEAT = b'[^']*'"
check "the watcher and the monitor agree on the longest line" \
  bash -c '[[ "$(grep -oE "^MAX_LINE = [0-9 *]+[0-9]" <<<"$1" | sed "s/^MAX_LINE = //")" == \
    "$(grep -oE "max-line-bytes\", type=int, default=[0-9 *]+[0-9]" "$2" | sed "s/.*default=//")" ]]' \
  _ "$WATCH" "$REPO/linux/agentlab-monitor.py"
if unshare --pid --fork --mount-proc true 2>/dev/null; then
  # The stand-in session and the watcher run as nobody, as the agent's are not
  # root, so a folder or file made unreadable is unreadable to the watcher too.
  AS=""
  command -v setpriv >/dev/null && AS="setpriv --reuid=65534 --regid=65534 --clear-groups"
  watch_case() {   # watch_case NAME: prints "<monitor exit> <early|held>"
    local home="$TMP/$1"
    mkdir -p "$home/bin" "$home/.claude/projects/-work-target"
    cp "$(command -v sleep)" "$home/bin/claude"
    chmod 755 "$TMP" "$home"
    AS="$AS" WATCH="$WATCH" MONITOR="$REPO/linux/agentlab-monitor.py" CASE="$1" HOME="$home" \
      unshare --pid --fork --mount-proc bash -c '
        prompt() { printf "{\"type\": \"user\", \"permissionMode\": \"%s\", \"message\": {\"content\": \"hi\"}}\n" "$1"; }
        big() {   # big FILE: 40 records of 200 kB, each in one write, as Claude Code writes them
          python3 -I -c "import os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND | os.O_CREAT)
rec = (\"{\\\"type\\\": \\\"user\\\", \\\"permissionMode\\\": \\\"auto\\\", \\\"message\\\": {\\\"content\\\": \\\"\" + \"x\" * 200000 + \"\\\"}}\n\").encode()
for _ in range(40):
    os.write(fd, rec)" "$1"
        }
        proj="$HOME/.claude/projects/-work-target"
        watcher="^python3 -I -\$"   # how ssh starts it: exec python3 -I -
        until_seen() { for _ in $(seq 1 40); do grep -q "$1" "$HOME/out.jsonl" 2>/dev/null && return 0; sleep 0.25; done; return 1; }
        until_done() { for _ in $(seq 1 "$1"); do [ -s "$HOME/rc" ] && return 0; sleep 0.25; done; return 1; }
        [ "$CASE" = stale ] && { prompt default > "$proj/old.jsonl"; sleep 1.1; }
        $AS "$HOME/bin/claude" 120 & claude=$!
        echo "$claude" > "$HOME/.agentlab-session.pid"
        # As agentlab-run does: the monitor reads a process substitution, so its
        # exit counts at once, even while the watcher is paused.
        { python3 -I "$MONITOR" --session --quiet --stall 3 --out "$HOME/out.jsonl" \
            < <($AS python3 -I - <<<"$WATCH" 2>/dev/null)
          echo "$?" > "$HOME/rc"; } &
        sleep 1.2                      # transcripts must be newer than the watcher
        prompt auto >> "$proj/new.jsonl"
        until_seen "\"auto\"" || { echo "never-followed"; kill "$claude"; exit; }
        case "$CASE" in
          leaves) prompt acceptEdits >> "$proj/new.jsonl" ;;
          clear)  sleep 1.1; prompt plan >> "$proj/cleared.jsonl" ;;
          init)   echo "{\"type\": \"system\", \"subtype\": \"init\"}" >> "$proj/new.jsonl" ;;
          kill)   pkill -f "$watcher" ;;
          swap)   mv "$proj/new.jsonl" "$proj/new.bak"; ln -s /dev/null "$proj/new.jsonl" ;;
          delete) rm "$proj/new.jsonl" ;;
          truncate) : > "$proj/new.jsonl" ;;
          fifo)   mkfifo "$proj/pipe.jsonl" ;;
          dirlink) mv "$proj" "$HOME/real"; ln -s "$HOME/real" "$proj" ;;
          unreadable) chmod 711 "$proj" ;;              # listable by no one but root
          writeonly) install -m 200 /dev/null "$proj/w.jsonl" ;;
          decoy)  mkdir -p "$HOME/.claude/projects/x"
                  prompt auto > "$HOME/.claude/projects/x/d.jsonl"
                  touch -d @4102444800 "$HOME/.claude/projects/x/d.jsonl"
                  sleep 2.5; prompt acceptEdits >> "$proj/new.jsonl" ;;
          flood)  mkdir -p "$HOME/.claude/projects/x"     # a decoy growing faster than it can be read
                  python3 -I -c "import os, sys, time
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
end = time.time() + 5
while time.time() < end:
    os.write(fd, b\"{}\\n\" * 100000)
    time.sleep(0.03)" "$HOME/.claude/projects/x/d.jsonl" &
                  sleep 1.5; prompt acceptEdits >> "$proj/new.jsonl" ;;
          interleave)   # both followed first, then written at once (a shared pipe mixed these)
                  prompt auto >> "$proj/other.jsonl"; sleep 2
                  big "$proj/new.jsonl" & w1=$!; big "$proj/other.jsonl" & w2=$!; wait "$w1" "$w2" ;;
          stop)   pkill -STOP -f "$watcher" ;;
          beatline) echo "{\"agentlab\": \"heartbeat\"}" >> "$proj/new.jsonl" ;;
          partial) printf "{\"type\": \"user\", \"permissionMode\": \"acceptEd" >> "$proj/new.jsonl" ;;
        esac
        until_done 16 && when=early || when=held
        kill "$claude"; pkill -CONT -f "$watcher" 2>/dev/null
        until_done 20
        echo "$(cat "$HOME/rc" 2>/dev/null || echo none) $when"'
  }
  check "watcher: a session that stays in auto mode is followed to its end" test "$(watch_case stays)" = "0 held"
  check "watcher: a prompt sent outside auto mode stops it" test "$(watch_case leaves)" = "3 early"
  check "watcher: a transcript from before the session is ignored" test "$(watch_case stale)" = "0 held"
  check "watcher: it follows the new transcript /clear starts" test "$(watch_case clear)" = "3 early"
  check "watcher: an init record written into the transcript stops it" test "$(watch_case init)" = "7 early"
  check "watcher: a decoy transcript can't hide the real one" test "$(watch_case decoy)" = "3 early"
  out="$(watch_case interleave)"
  check "watcher: large records from two transcripts written at once arrive whole [$out]" test "$out" = "0 held"
  out="$(watch_case flood)"
  check "watcher: a growing decoy can't hold it on one file [$out]" test "$out" = "3 early"
  out="$(watch_case stop)"
  check "watcher: a paused watcher goes quiet, and that stops it [$out]" test "$out" = "8 early"
  out="$(watch_case partial)"
  check "watcher: a record left unfinished at the end isn't sent as a line [$out]" test "$out" = "0 held"
  hiding="dirlink"
  [[ -n "$AS" ]] && hiding="dirlink unreadable writeonly" || skip "no setpriv: the unreadable-file cases need a non-root watcher"
  for c in kill swap delete truncate fifo beatline $hiding; do
    out="$(watch_case "$c")"
    check "watcher: tampering ($c) ends the watcher while the session runs [$out]" grep -q ' early$' <<<"$out"
  done
  check "watcher: the gateway keeps a copy of what it followed" grep -q '"permissionMode": "auto"' "$TMP/stays/out.jsonl"
  check "watcher: the copy holds every large record whole" \
    test "$(awk 'length($0) > 200000 { n++ } END { print n + 0 }' "$TMP/interleave/out.jsonl")" -eq 80
else
  skip "PID namespaces unavailable here; skipping the session watcher"
fi

NS=agentlab-test-preflight PEER=agentlab-test-preflight-peer
ip netns del "$NS" 2>/dev/null; ip netns del "$PEER" 2>/dev/null   # left by a crashed run
if ! ip netns add "$NS" 2>/dev/null; then
  skip "network namespaces unavailable here; skipping the preflight's route checks"
  finish; exit
fi
ip netns add "$PEER"
trap 'ip netns del "$NS" 2>/dev/null; ip netns del "$PEER" 2>/dev/null; rm -rf "$TMP"' EXIT
X() { ip netns exec "$NS" "$@"; }
# Like the sandbox after cutover: IPv6 off, one interface, one address on the lab subnet.
X sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
X ip link set lo up
X ip link add eth0 type veth peer name eth0p netns "$PEER"
ip netns exec "$PEER" ip link set eth0p up
X ip addr add 10.77.0.10/24 dev eth0; X ip link set eth0 up
net_problems() { X bash -c "$NET_CHECKS" 2>/dev/null; }

check "a sandbox with only the lab subnet passes" test -z "$(net_problems)"
X ip route add 192.0.2.0/24 via 10.77.0.1
check "a route to one outside network is refused" grep -q "route beyond" <<<"$(net_problems)"
X ip route del 192.0.2.0/24 via 10.77.0.1
X ip route add default via 10.77.0.1
check "a default route is refused" grep -q "route beyond" <<<"$(net_problems)"
X ip route del default via 10.77.0.1
X ip route add default via 10.77.0.1 table 100; X ip rule add pref 100 lookup 100
check "a route in another routing table is refused" grep -q "route beyond" <<<"$(net_problems)"
X ip rule del pref 100; X ip route del default via 10.77.0.1 table 100
X ip link add eth1 type dummy 2>/dev/null || X ip link add eth1 type veth peer name eth1p
check "a second interface is refused" grep -q "exactly one network interface" <<<"$(net_problems)"
X ip link del eth1
X ip addr del 10.77.0.10/24 dev eth0; X ip addr add 10.77.0.20/24 dev eth0
check "another address is refused" grep -q "isn't 10.77.0.10/24" <<<"$(net_problems)"
check "with no lab route, an empty read is refused" grep -q "no route to 10.77.0.0/24" \
  <<<"$(ip netns exec "$NS" env PATH=/nonexistent /bin/bash -c "$NET_CHECKS" 2>/dev/null)"
X ip addr del 10.77.0.20/24 dev eth0; X ip addr add 10.77.0.10/24 dev eth0
if X sysctl -qw net.ipv6.conf.eth0.disable_ipv6=0 2>/dev/null && X ip -6 addr add fd77::10/64 dev eth0 nodad 2>/dev/null; then
  check "an IPv6 address is refused" grep -q "IPv6 address" <<<"$(net_problems)"
else
  skip "IPv6 isn't available here, so the preflight's IPv6 check isn't tested"
fi
finish
