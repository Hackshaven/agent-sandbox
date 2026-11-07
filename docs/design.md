# Design

Two Hyper-V VMs on a private switch. The **sandbox VM** runs Claude Code and the
target, with no route out. The **gateway VM** holds the Claude token, forwards
model calls and nothing else, and keeps every log. This adapts the credential-proxy
pattern in Anthropic's agent containment guidance for Cyber Verification Program
participants to a Windows 11 laptop, which their Linux/KVM reference design
doesn't cover.

![Lab layout: the sandbox reaches only port 8080 on the gateway; only the gateway reaches api.anthropic.com](lab-layout.svg)

The scripts in this repo are the implementation. This page explains why each
control exists and where the build falls short of the guidance.

## Why not WSL2 or Docker Desktop

Anthropic's reference design lists Windows, Docker Desktop and WSL2 as hosts it
won't work on. Plain containers share the host kernel, so a kernel exploit in a
container is a host compromise. WSL2 also mounts the C: drive and can launch
Windows programs by default. Both stay in use for normal work and out of the lab.
Docker still has a job: rootless Docker runs local targets *inside* the sandbox VM.

## How the build meets the guidance

| Property the guidance asks for | How this build does it | Where |
| --- | --- | --- |
| Agent has its own guest kernel | Hyper-V Gen 2 VM | `agentlab.ps1 build` |
| No host directory shared into the guest | No shared folders; Guest Service Interface and KVP off; `hv_sock` blocked from loading | `agentlab.ps1 build`, `sandbox-setup.sh install` |
| Model credential not in the agent's environment or disk | Token lives in a root-only nginx include on the gateway; the sandbox holds a placeholder | `gateway-setup.sh`, `sandbox-setup.sh install` |
| No internet; egress enforced outside the guest | Private switch, no default route or DNS in the sandbox, nftables on the gateway drops and logs everything except `10.77.0.10 → 10.77.0.1:8080` | `gateway-setup.sh`, `sandbox-setup.sh cutover` |
| Proxy forwards model calls only | Exact-match allowlist (`POST /v1/messages`, `/v1/messages/count_tokens`); everything else 403; client auth headers stripped | `gateway-setup.sh` |
| No cloud metadata reachable | Not on a cloud host; the gateway refuses to route | `gateway-setup.sh` |
| Turn and time limit on every run | `--max-turns` and `timeout`, validated before launch; unreadable limits refuse to start, and so does a zero time limit, which `timeout` reads as none | `agentlab-run`, `agentlab.ps1 run` |
| No privileged mode or added capabilities | Agent has no sudo and isn't in `docker`, `adm` or `lxd`; Docker is rootless | `sandbox-setup.sh install` |
| Orchestrator and transcripts on the trusted side | Runs launch from the gateway; transcripts and logs are written there | `agentlab-run` |
| Auto mode as defense in depth, never `bypassPermissions` | Managed settings set `defaultMode: auto` and disable bypass; environment and tampering rules describe the lab; the No-network rule is added only after checks pass | `sandbox-setup.sh install`, `finalize` |
| Setup phase, then attack phase | Tools installed with internet in `install`; `cutover` is permanent; changes go through `reopen` and a re-check | `sandbox-setup.sh` |
| Test the sandbox before relying on it | Config checks, hand checks and a supervised escape test, repeated after any sandbox or model change | `agentlab-check.sh`, `templates/escape-test.md` |
| Keep transcripts and logs 30+ days, review them | 45-day retention; per-run evidence folder; pattern scan; new proxy refusals and firewall denies printed after each run | `gateway-setup.sh`, `agentlab-run`, `agentlab-scan.py` |
| Stop on repeated denials | Monitor ends a run after 3 denials in a row or 20 total, and if the run isn't in auto mode | `agentlab-monitor.py` |
| Scope stated as intent in every task | Runs refuse a task file without a `## Scope` section | `agentlab-run`, `templates/task-template.md` |

The firewall logs every protocol, not just refused HTTPS. That closes a gap the
guidance notes in its own design, where plain-HTTP and raw TCP attempts leave no
proxy log line.

## Where this falls short

| Guidance | This build | Mitigation |
| --- | --- | --- |
| Dedicate the host; assume an agent could read anything on it | An everyday laptop, with Hyper-V the only layer between the sandbox and everything else | Keep runs short and watched. For long unattended batches, move this design to a spare Linux machine with KVM |
| Run the escape test on a host you can rebuild | The VM reverts; the laptop doesn't | Watch the test live and stop at the first odd move |
| Sandbox escape classifier score | Not available to agents in Claude Code | Transcript and log review |
| Proxy forwards model calls only | The path allowlist is a starting guess | Tune it from 403 lines after the first real run |
| Treat auto mode rules as security config | Root-owned managed settings; the agent isn't root | Recheck `claude auto-mode config` after every Claude Code update |

Whatever the agent sends to the model, including target code and findings, leaves
the network in request bodies the proxy doesn't log.

## Not in v1: work against real networks

Leave this until local runs are clean and routine. Reach to real hosts changes the
risk more than anything else here. When the time comes:

- Allowlist the in-scope targets on the gateway (a forward proxy for HTTP, tightly
  scoped forwarding rules otherwise). Never add the model API host to it.
- Name the targets for auto mode in `environment`, so its containment rules apply
  only outside that range.
- Prefer a staging or replica environment disconnected from production.
- Watch every networked run live, with the ability to stop it at once.
- Add a lab VLAN on the home UniFi network whose firewall permits only the in-scope
  targets, with logging on.
- NOAA targets need ITSO sign-off per engagement, and the approval should cover
  target code and findings going to Anthropic in model requests. Keep autonomous
  agents off live production and safety-critical systems; a person makes every
  state-changing step.

The gateway contains the agent's own traffic, not traffic a networked target sends
on its behalf.

## Decisions worth knowing

- **Token type.** A `claude setup-token` OAuth token for the Pro/Max account with
  Defense Access, forwarded as `Authorization: Bearer`. An API key would need a
  different proxy header.
- **Proxy on a second VM, not localhost.** Anthropic's checklist says "a proxy on
  localhost"; its reference design uses a separate container on the agents'
  network. A separate VM is the closer match on Hyper-V and keeps the token outside
  the sandbox's kernel entirely.
- **Root-owned Claude Code binary.** The installer puts Claude Code in the agent's
  home, where the agent could modify it. `install` copies it to `/usr/local/bin`
  owned by root and removes the agent's copy.
- **`/etc/environment`, not a profile script.** It also applies to commands launched
  over SSH, which is how runs start.
- **SSH drop-in named `00-`.** Ubuntu reads `sshd_config.d` before the main file, the
  first value wins, and the installer's `50-cloud-init.conf` turns passwords on.
- **`client_max_body_size 64m`.** nginx's 1 MB default rejects long agent requests.
- **`net.ipv4.ip_nonlocal_bind`.** Lets nginx bind `10.77.0.1` at boot before the
  address is up.

## Sources

See [sources.md](sources.md).
