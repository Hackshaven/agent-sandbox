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

## Review agents

`.claude/agents/` holds a review team of ten agents installed from the
[agency-agents catalog](https://github.com/Hackshaven/agency-agents/blob/hackshaven/strategy/runbooks/scenario-agent-sandbox.md)
by its agent-sandbox runbook, which gives the reasoning behind each row below.
They are a second reader for changes a model wrote, not a substitute for a
person. Agents read code and config; only the isolation checks and the watched
escape test verify a real build.

- **When.** Before reporting a change done or opening a PR, route it by the paths
  it touches and run each matching reviewer through the Agent tool, with
  `subagent_type` set to the name in the table exactly as written. Every code
  change gets at least one: the specialist for each matching row, or the
  `Code Reviewer` when none matches. A change that matches several rows runs all
  of them. A docs-only change needs none unless a row names the doc.
- **Boundary changes get two.** A change to any item under "The boundary comes
  first" gets its specialist plus the `Code Reviewer`, and the PR says whether the
  escape test must run again before the next real run (the README requires it
  after any sandbox or model change).
- **Reviewers report; they don't edit.** Findings come back with `file:line`. You
  fix, and the owner decides what stands.
- **This file wins.** Where an agent's general advice conflicts with the rules
  above (a vault for the token, a prefix location to clear a 403, bypass mode to
  get a run going), this file wins. Where a doc describes the code and the code
  disagrees, report the mismatch and let the owner decide which is right. Never
  rewrite a statement of the boundary to match weaker code.
- **No probing the lab.** Reviewers work in the host session and never connect to
  the lab VMs. A probe runs in `tests/` (network namespaces, a mock upstream) or
  becomes an attempt in `templates/escape-test.md`. Only this instruction stops
  them: the agent files carry no tool restrictions.
- **Don't hand-edit the agent files.** The Agency Agents app recognizes each by its
  exact content and restores the catalog's copy on its next Update, so change them
  in the catalog. `.gitattributes` keeps them LF so a Windows checkout matches.

| If the change touches… | Run |
|---|---|
| nftables, sysctl, netplan and interface detection in `gateway-setup.sh`; `phase_cutover` in `sandbox-setup.sh`; the network checks in `agentlab-check.sh`; `tests/test_firewall.sh` | `Security Architect`, `Code Reviewer`, `Network Engineer`; `Penetration Tester` as second reader |
| The nginx site and upstream heredocs in `gateway-setup.sh`; `tests/test_proxy.sh`. A new path goes in the heredoc, never only in the live config | `Security Architect`, `Code Reviewer`; `Penetration Tester` as second reader |
| The token: its section of `gateway-setup.sh`, the proxy's auth and header-stripping lines and `log_format`, the sandbox's placeholder and `ANTHROPIC_API_KEY` removal, the token checks in `agentlab-check.sh` and the `agentlab-run` preflight, the token assertions in `tests/test_proxy.sh`, `.gitignore`, any token-shaped test value, the README's rotation step | `Secrets & Credential Hygiene Engineer`, `Security Architect`, `Code Reviewer` |
| The SSH section of `gateway-setup.sh` (the run key), `SSH_OPTS` in `agentlab-run`, the restricted `authorized_keys` line in `phase_install` | `Secrets & Credential Hygiene Engineer`, `Security Architect` |
| Managed settings: `write_managed_settings` and `phase_finalize` in `sandbox-setup.sh`, their checks in `agentlab-check.sh`, the monitor's `permissionMode` handling, `--permission-mode` in `agentlab-run` | `Security Architect`, `Code Reviewer`; `Prompt Engineer` for rule text |
| Sandbox isolation: `agentlab.ps1` `build`, `cutover`, `reopen` and `check`; `phase_install`, `install_rootless_docker` and `phase_reopen` in `sandbox-setup.sh`; the rest of the sandbox half of `agentlab-check.sh` | `Security Architect`, `Code Reviewer`; `Penetration Tester` as second reader |
| Run limits, refusals and the run lifecycle: validation, preflight, input delivery, launch, `stop_remote` and the trap in `agentlab-run`; `agentlab.ps1` `run`, `stop`, `revert` and `baseline`; `templates/task-template.md` | `Code Reviewer`, `Security Architect`; `Prompt Engineer` for the template |
| `agentlab-scan.py`, the monitor's denial patterns and budgets, `tests/test_transcripts.py` | `Threat Detection Engineer`, plus the `Code Reviewer` for code |
| Anything on the gateway that prints, parses or unpacks sandbox output: the monitor's view, `scan.txt`, the review block and preflight echoes in `agentlab-run`, the interactive session, the "Logs" output of `agentlab-check gateway`, `claude-projects.tgz` | `Security Architect` |
| Evidence and retention: `collect()`, the run folder and the review block in `agentlab-run`, the transcript the monitor writes, the logging section of `gateway-setup.sh`, the README's "A hit during a run" | `Incident Responder`, plus the `Code Reviewer` for code |
| `templates/escape-test.md` | `Penetration Tester`; `Prompt Engineer` for the wording |
| Any other part of `agentlab-check.sh` | `Code Reviewer`, plus the reviewer for what the check covers |
| `tests/lib.sh`, `tests/run-all.sh` | `Code Reviewer`, plus the `Security Architect` when a change alters what the boundary tests render |
| The boundary and "Still unverified" sections of this file; the README's "Known limits" and "Testing" | `Security Architect`, then the owner |
| The README's build, run and maintenance steps | `Technical Writer` |
| `docs/design.md`, `docs/lab-layout.svg`, `docs/sources.md` | `Security Architect` |
| Anything else in `linux/`, `windows/`, `tests/` or `.github/`, and `.gitattributes` | `Code Reviewer` |

A merged gateway change takes effect only after `linux/` is copied to the gateway
again and `gateway-setup.sh` is rerun, because that script writes the firewall and
proxy config and installs copies of the `agentlab-*` commands.

The `Codebase Archaeologist` runs quarterly and after a Claude Code update. It
checks "Still unverified" below and the README's "Known limits" against the
evidence, the guidance table in `docs/design.md` against the scripts,
`docs/sources.md` against guidance pages that may have moved, and the values
repeated across scripts (addresses, `MIN_CLAUDE`, the managed-settings path, the
privileged groups, the denial patterns, retention, limit validation) against each
other. The installed commands are copied one by one into `/usr/local/bin` or
`/usr/local/sbin`, where none can source a sibling file, so drift between copies
is the finding.

No catalog agent knows agent containment. The runbook proposes one. Until it
exists, the `Security Architect` is the gate for the boundary and the
`Penetration Tester` its second reader.

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
