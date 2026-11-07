# CLAUDE.md

This repo builds a security boundary: a Hyper-V sandbox VM where Claude Code does
defensive security work with no route out, and a gateway VM that holds the Claude
token and forwards only model calls. Read `README.md` and `docs/design.md` first.

## The boundary comes first

Treat every change to these as a security change. Make it only when asked, say
plainly what it widens, and update `docs/design.md` in the same commit:

- `linux/gateway-setup.sh` nftables rules: the sandbox (10.77.0.10) may open
  connections to 10.77.0.1:8080 and nothing else.
- The nginx allowlist: exact paths, model calls only. Add a path only when a
  `credproxy.log` 403 shows Claude Code needs it and it is a model call. Never add a
  catch-all or prefix location.
- Where the token lives: only `/etc/nginx/agentlab-token.conf` on the gateway.
  Never put a real token, key or credential in the sandbox, in this repo, in tests,
  or in a commit message. Tests use obviously fake values.
- Auto mode: managed settings keep `defaultMode: auto` and disable
  `bypassPermissions`. Never suggest `--dangerously-skip-permissions` or bypass mode.
  Rule lists start with `"$defaults"`.
- Sandbox isolation: one adapter on the AgentLab switch, Guest Service Interface and
  KVP off, `hv_sock` blocked, no shared folders, agent without sudo or docker group.
- Run limits and refusals in `agentlab-run`: unreadable limits refuse to launch, a
  task without `## Scope` refuses, a sandbox with a route out refuses.

If a fix would weaken one of these to make something work, stop and explain the
tradeoff instead.

## Where work happens

Building, debugging and testing this lab from the Windows host is normal dev work.
Security work itself (analyzing targets, exploit validation) runs inside the
sandbox through `agentlab.ps1 run`, not in a host session.

## Before committing

- `bash tests/run-all.sh` (in WSL or Linux). Use `sudo` to include the firewall
  namespace tests. All must pass; CI runs the same on push.
- `shellcheck -S warning` clean for every shell script.
- Behavior changes get a test in `tests/` when the logic can be exercised without
  the real VMs (proxy, firewall, scanner, monitor).
- Keep the README steps, `docs/design.md` and the scripts in agreement.

## Conventions

- American English in prose, comments and messages.
- Linux scripts keep LF endings (`.gitattributes` enforces this); keep the execute
  bit on `linux/*` and `tests/*.sh`.
- Generated config files start with a "Written by <script>" comment, and setup
  scripts stay safe to re-run.
- `agentlab.ps1` targets Windows PowerShell 5.1 and PowerShell 7, runs elevated,
  and uses only the Hyper-V module plus built-ins.

## Still unverified

The README's "Known limits" list is the source of truth. As of the first commit:
`agentlab.ps1` has never run against Hyper-V; the auto mode denial text in
`agentlab-monitor.py` and `agentlab-scan.py` is a guess; it's untested whether auto
mode works with a custom `ANTHROPIC_BASE_URL` on this plan, which extra paths
Claude Code requests, and whether `/etc/claude-code/managed-settings.json` is read.
When one of these is confirmed or fixed, update that list.
