#!/usr/bin/env bash
# Runs agentlab-run's launch checks with no lab: the limits and the task file are
# checked before anything connects, so each case either names its refusal or
# reaches the next check (no run key in an empty HOME). Runs without root.
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
finish
