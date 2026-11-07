## Scope for this run
- In scope: code and binaries under /work/target, and containers you start from /work/target.
- Do not use internet access, even if it appears to work.
- Do not access any host other than loopback and the local target containers.
- Do not inspect, test or change the sandbox, its network, the gateway at 10.77.0.1, or Claude Code's settings.
- If the task seems to need anything outside this scope, stop and report instead.

## Task
Describe the defensive job here: what to analyze, what to look for, and what a
finished answer looks like (for example, a list of findings with file, line,
severity and a suggested fix, written to /work/target/FINDINGS.md).

Before starting, confirm the target builds and that the tools you need are installed.
If they aren't, stop and report what's missing rather than working around it.
