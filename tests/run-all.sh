#!/usr/bin/env bash
# Run every check that doesn't need the real VMs:
#   lint (bash -n, shellcheck), transcript tools, run launcher checks,
#   credential proxy, firewall.
# The firewall namespace tests need root; run with sudo to include them.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
status=0

echo "lint"
mapfile -t scripts < <(printf '%s\n' linux/*.sh linux/agentlab-run tests/*.sh)
for f in "${scripts[@]}"; do
  bash -n "$f" || { echo "  FAIL  bash -n $f"; status=1; }
done
if command -v shellcheck >/dev/null; then
  if shellcheck -S warning -x "${scripts[@]}"; then echo "  ok    shellcheck"; else status=1; fi
else
  echo "  skip  shellcheck not installed"
fi
python3 -m py_compile linux/agentlab-monitor.py linux/agentlab-scan.py && echo "  ok    python compiles" || status=1
rm -rf linux/__pycache__

echo "transcript tools"
python3 -m unittest -q tests/test_transcripts.py || status=1

bash tests/test_run.sh || status=1
bash tests/test_proxy.sh || status=1
bash tests/test_firewall.sh || status=1

echo
if (( status == 0 )); then echo "all tests passed"; else echo "SOME TESTS FAILED"; fi
exit "$status"
