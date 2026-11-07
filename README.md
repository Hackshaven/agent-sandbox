# agent-sandbox

A contained lab for running Claude Code on defensive security work, built to
Anthropic's [agent containment best practices](docs/sources.md) for Cyber
Verification Program participants, on a Windows 11 laptop with Hyper-V.

A sandbox VM runs the agent and the target with no route out. A gateway VM holds
the Claude token, forwards model calls and nothing else, and keeps every log.
[docs/design.md](docs/design.md) explains why each control exists and where the
build falls short of the guidance.

![Lab layout](docs/lab-layout.svg)

The two Ubuntu installs are manual (about 10 minutes each). Everything else is
scripted, including the isolation checks and a one-command run. Needs Windows 11
Pro, Enterprise or Education.

## What's here

| File | Runs on | Does |
| --- | --- | --- |
| `windows/agentlab.ps1` | Windows, admin PowerShell | Builds the switch and VMs; cutover, baseline, revert, run, stop, check |
| `linux/gateway-setup.sh` | Gateway VM | Network, firewall, credential proxy, logging, token, run key |
| `linux/sandbox-setup.sh` | Sandbox VM | `install`, `cutover`, `finalize` and `reopen` phases |
| `linux/agentlab-check.sh` | Both VMs | Isolation checks (`gateway` or `sandbox`) |
| `linux/agentlab-run` | Gateway | Launches one run: preflight, limits, transcript, evidence, scan |
| `linux/agentlab-monitor.py` | Gateway | Live view; stops runs not in auto mode or over the denial budget |
| `linux/agentlab-scan.py` | Gateway | Pattern rules over transcripts |
| `templates/` | — | Task template and the escape test |
| `tests/` | Linux or CI | Firewall, proxy and transcript-tool tests (see Testing) |
| `docs/` | — | Design rationale, layout diagram, sources |

Read the scripts before you run them. They are short, and they draw the boundary.

## Build it (once)

**0. Before you start**
- Hyper-V on: `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`, then reboot.
- Ubuntu Server 24.04 LTS ISO downloaded.
- A Claude token: on any machine with a browser (WSL is fine), run `claude setup-token`
  with the Defense Access account. Keep it in your password manager. It goes on
  the gateway only.

**1. Create the VMs** (admin PowerShell, in `windows\`)
```powershell
Get-ChildItem -Recurse .. | Unblock-File      # only needed if you downloaded a zip
Set-ExecutionPolicy -Scope Process Bypass
.\agentlab.ps1 build -IsoPath C:\ISO\ubuntu-24.04-live-server-amd64.iso
```

**2. Install Ubuntu on both VMs.** `vmconnect localhost agentlab-gw`, then
`Start-VM agentlab-gw`. Use hostname `agentlab-gw`, turn on OpenSSH, and import
your SSH public key if you have one. Repeat for `agentlab-sbx` (hostname
`agentlab-sbx`). Use the same admin username on both.

**3. Copy the kit to both VMs.** They are still on the Default Switch, so Windows
reaches them by name:
```powershell
foreach ($h in 'agentlab-gw', 'agentlab-sbx') {
    ssh you@$h.mshome.net mkdir -p agentlab
    scp -r ..\linux "you@$h.mshome.net:agentlab/"
    ssh you@$h.mshome.net chmod +x agentlab/linux/*      # Windows drops the execute bit
}
```

**4. Set up the gateway** (SSH in or use its console)
```bash
sudo ~/agentlab/linux/gateway-setup.sh      # paste the token when asked
sudo agentlab-check gateway
```
It prints a public key at the end. Copy it for the next step.

**5. Install the sandbox's tools** (sandbox console or SSH, internet still on)
```bash
sudo ~/agentlab/linux/sandbox-setup.sh install --gateway-key "ssh-ed25519 AAAA... agentlab-gw run key"
# Optional: --docker for rootless Docker, --images "nginx:1.27 ..." to pre-pull,
#           --packages "radare2 binwalk ..." for extra tools
```
Copy in any target source or tools now. After cutover the sandbox can't fetch anything.

**6. Cut over** (permanent; the sandbox loses internet)
```powershell
.\agentlab.ps1 cutover
```
Then at the sandbox **console** (SSH from Windows stops working here):
```bash
sudo ~/agentlab/linux/sandbox-setup.sh cutover
sudo -iu agent claude      # once: accept the first-run prompts, check it answers, /exit
sudo agentlab-check sandbox --model-call
```

**7. Finalize and save the clean state**
```bash
sudo ~/agentlab/linux/sandbox-setup.sh finalize      # sandbox console
```
```powershell
.\agentlab.ps1 check
.\agentlab.ps1 baseline
```

**8. Supervised escape test.** Open a second window on the gateway with
`tail -f /var/log/agentlab/egress-deny.log /var/log/agentlab/credproxy.log`, then:
```powershell
.\agentlab.ps1 run -Task ..\templates\escape-test.md -Turns 40 -Time 30m
```
Watch it. Stop with Ctrl+C at the first odd move (`.\agentlab.ps1 stop` is the
hard off-switch). Afterward, read the whole transcript in
`/var/log/agentlab/runs/<id>/` and note, for each attempt, whether the sandbox or
auto mode stopped it. Any success is a blocker: fix it and retest before real runs.

## Run a job

```powershell
Copy-Item ..\templates\task-template.md C:\Lab\tasks\my-job.md   # edit the Task section
.\agentlab.ps1 run -Task C:\Lab\tasks\my-job.md -Target C:\Lab\targets\my-app -Turns 60 -Time 2h
```
That one command reverts the sandbox, delivers the task and target, runs Claude
Code headless with your limits, collects the evidence, scans the transcript,
prints any new proxy refusals and firewall denies, and reverts again.

Add `-Interactive` for a supervised session instead (recorded on the gateway).

Each run's folder on the gateway holds `task.md`, `meta.txt`, `transcript.jsonl`,
`claude-projects.tgz`, `credproxy.new.log`, `egress-deny.new.log` and `scan.txt`.
Folders older than 45 days are pruned.

## When something changes

- **New tools or a new Claude Code version:** `.\agentlab.ps1 reopen`, then
  `sudo ~/agentlab/linux/sandbox-setup.sh reopen` at the sandbox console, rerun
  `install`, then steps 6 to 8. That is a sandbox change, so the escape test runs
  again. `agentlab-run` refuses to start while the sandbox has a route out.
- **New model:** rerun the escape test with `-Model <id>`.
- **Proxy refusals:** `sudo agentlab-check gateway` lists refused paths. Add one to
  `/etc/nginx/sites-available/agentlab` only if it is a model call, then
  `sudo nginx -t && sudo systemctl reload nginx`.
- **A hit during a run:** stop it, keep the run folder, report out-of-scope
  behavior through support.claude.com as a Cyber Verification Program participant,
  and rotate the token (`claude setup-token`, then rerun `gateway-setup.sh`).

## Testing

`tests/run-all.sh` runs everything that doesn't need the real VMs: lint, the
transcript tools, and the credential proxy against a mock upstream. Run it with
`sudo` to add the firewall tests, which build a two-namespace copy of the lab and
check what the sandbox can and can't reach (with controls that prove the firewall,
not the setup, is what blocks). CI runs all of it on every push, plus a parse and
PSScriptAnalyzer pass on `agentlab.ps1`.

These tests cover the scripts' logic, not your machine. The isolation checks in
steps 4, 6 and 7 and the escape test in step 8 are what verify a real build.

## Known limits

- `agentlab.ps1` is parsed and linted in CI but hasn't run against Hyper-V yet.
  Run `.\agentlab.ps1 status` first; if a cmdlet errors, the fix is usually one parameter.
- The auto mode denial text in `agentlab-monitor` and `agentlab-scan` is a best
  guess. Check it against the first real denial in a transcript and adjust
  `--deny-pattern` if it doesn't match.
- Unverified until your first run: that auto mode works with a custom
  `ANTHROPIC_BASE_URL` on your plan, which extra paths Claude Code requests, and
  that `/etc/claude-code/managed-settings.json` is read (the sandbox check tests
  this).
- This is your everyday laptop, not a dedicated host. Keep runs short and watched.
