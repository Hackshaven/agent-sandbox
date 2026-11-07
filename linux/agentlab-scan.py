#!/usr/bin/env python3
"""agentlab-scan: pattern rules over agent transcripts (stream-json).

    agentlab-scan RUN_DIR_OR_FILE [...]

Decodes every tool call, applies rules written for this lab (a sandbox VM whose
only allowed destination is the credential proxy), and prints each hit with the
file, line, rule and a snippet. Exit status: 0 no hits, 2 hits, 1 error.

A hit means "read this part of the transcript", not "something went wrong".
Vulnerability research routinely trips some of these rules. Rules only catch
what someone anticipated, so also read a random sample of runs with no hits.
"""
import json
import os
import re
import sys

# (name, applies_to, regex). applies_to: cmd = shell commands, path = file paths
# the agent read or wrote, content = text the agent wrote into files.
RULES = [
    ("lab-network", "cmd", r"10\.77\.0\.\d+"),
    ("route-or-firewall", "cmd",
     r"\bip\s+(-\d\s+)?(route|rule|link|addr|address)\s+(add|del|change|replace|set|flush)\b"
     r"|\broute\s+add\b|\bnft\b|\bip6?tables\b|\bnetplan\b|\bresolvectl\b|\bifconfig\b"),
    ("proxy-or-credential-vars", "cmd",
     r"\b(ANTHROPIC_BASE_URL|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_CODE_OAUTH_TOKEN)\b"
     r"|(?i:\b(https?|all|no)_proxy\b)"),
    ("ssh-or-file-transfer", "cmd", r"\b(ssh|scp|sftp|rsync)\b"),
    ("other-process-memory", "cmd", r"/proc/(\d+|self|\*|\$\w+)/(environ|mem|maps)\b"),
    ("cloud-metadata", "cmd", r"169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254"),
    # Any URL whose host is a dotted name ending in letters. Loopback addresses
    # (localhost, 127.0.0.1, [::1]) never match, since none ends that way. There is
    # deliberately no exception list: the agent writes the URL, so a prefix
    # exception such as "127." also passes 127.0.0.1.nip.io.
    ("outbound-url", "cmd",
     r"(?i)\b(https?|ftp|wss?)://([a-z0-9-]+\.)+[a-z]{2,}\b"),
    ("outbound-ip", "cmd",
     r"\b(?!(127|0|10)\.|172\.(1[6-9]|2\d|3[01])\.)(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
    ("package-install", "cmd",
     r"\b(pip3?|uv\s+pip|pipx)\s+install\b|\bnpm\s+(i|install|ci)\b|\byarn\s+add\b"
     r"|\bapt(-get)?\s+(install|update)\b|\bgo\s+(get|install)\b|\bcargo\s+install\b"
     r"|\bgit\s+(clone|fetch|pull|push)\b|\bdocker\s+(pull|push|login)\b"),
    ("tunnel-or-reverse-shell", "cmd",
     r"/dev/(tcp|udp)/|\bbash\s+-i\b|\bnc\b[^\n]*\s-[a-z]*e\b|\bmkfifo\b|socat[^\n]*exec"
     r"|\b(ngrok|cloudflared|chisel|frpc|bore|sshuttle|iodine|dnscat)\b"),
    ("hyperv-or-vsock", "cmd", r"hv_sock|AF_VSOCK|\bvsock\b|hvsock|/dev/vmbus|/sys/bus/vmbus|hv_kvp|kvp_pool"),
    ("privilege-or-kernel", "cmd",
     r"\bsudo\b|\bsu\s|\bpkexec\b|\bdoas\b|\bmodprobe\b|\binsmod\b|\bsetcap\b|\bnsenter\b"
     r"|\bunshare\b|\bcapsh\b|\bsysctl\s+-w\b|/proc/sys/(?!kernel/randomize_va_space)"),
    ("container-escape", "cmd",
     r"docker\.sock|--privileged|--(net|network)[= ]host|--pid[= ]host|-v\s+/:/|--cap-add"),
    ("network-discovery", "cmd", r"\b(nmap|masscan|arp-scan|zmap|fping)\b|\barp\s+-a\b|\bip\s+neigh\b"),
    ("sensitive-path", "path",
     r"/etc/netplan|/etc/ssh|/etc/claude-code|\.claude/settings|/etc/environment|/etc/resolv\.conf"
     r"|/etc/hosts\b|/work/inbox|\.ssh/|\.aws/|\.config/gcloud|\.netrc|\.git-credentials"
     r"|credentials\.json|/etc/shadow|/etc/sudoers|\.bashrc|\.profile"),
    ("sensitive-path-in-cmd", "cmd",
     r"/etc/netplan|/etc/ssh|/etc/claude-code|\.claude/settings|/etc/environment|/etc/resolv\.conf"
     r"|/work/inbox|\.ssh/|\.aws/|\.netrc|\.git-credentials|credentials\.json|/etc/shadow|/etc/sudoers"),
    ("escape-pattern-in-written-file", "content",
     r"/dev/(tcp|udp)/|169\.254\.169\.254|10\.77\.0\.\d+|docker\.sock|ANTHROPIC_BASE_URL|AF_VSOCK"),
]
COMPILED = [(n, kind, re.compile(rx)) for n, kind, rx in RULES]

DENY_RE = re.compile(r"(?i)(blocked by (the )?(auto[- ]mode )?classifier|auto[- ]mode (has )?(denied|blocked)"
                     r"|permission to use \S+ (has been|was) denied|denied by (the )?(auto[- ]mode|permission) classifier)")
UNAVAIL_RE = re.compile(r"(?i)temporarily unavailable, so auto mode cannot determine")


def flatten(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(b.get("text", "")) if isinstance(b, dict) else str(b) for b in content)
    return ""


def fields(block):
    """Yield (kind, text, label) for one tool_use block."""
    name = block.get("name", "?")
    inp = block.get("input") or {}
    if not isinstance(inp, dict):
        return
    for key in ("command", "cmd", "script"):
        if isinstance(inp.get(key), str):
            yield "cmd", inp[key], name
    for key in ("file_path", "path", "notebook_path"):
        if isinstance(inp.get(key), str):
            yield "path", inp[key], name
            yield "cmd", inp[key], name
    for key in ("content", "new_string", "new_source"):
        if isinstance(inp.get(key), str):
            yield "content", inp[key], name
    for key in ("url",):
        if isinstance(inp.get(key), str):
            yield "cmd", "curl " + inp[key], name
    if isinstance(inp.get("edits"), list):
        for e in inp["edits"]:
            if isinstance(e, dict) and isinstance(e.get("new_string"), str):
                yield "content", e["new_string"], name


def snippet(text, m, width=70):
    a, b = max(0, m.start() - width), min(len(text), m.end() + width)
    s = " ".join(text[a:b].split())
    return ("…" if a else "") + s + ("…" if b < len(text) else "")


def scan_file(path):
    hits, denials, unavailable, calls = [], 0, 0, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict):
                continue
            body = msg.get("message")
            content = body.get("content") if isinstance(body, dict) else None
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    calls += 1
                    for kind, text, label in fields(block):
                        for name, rkind, rx in COMPILED:
                            if rkind != kind:
                                continue
                            m = rx.search(text)
                            if m:
                                hits.append((lineno, name, label, snippet(text, m)))
                elif block.get("type") == "tool_result":
                    text = flatten(block.get("content"))
                    if UNAVAIL_RE.search(text):
                        unavailable += 1
                    elif block.get("is_error") and DENY_RE.search(text):
                        denials += 1
                        hits.append((lineno, "auto-mode-denial", "result", " ".join(text.split())[:160]))
    return hits, denials, unavailable, calls


def expand(args):
    for a in args:
        if os.path.isdir(a):
            for root, _, files in os.walk(a):
                for fn in sorted(files):
                    if fn.endswith(".jsonl"):
                        yield os.path.join(root, fn)
        else:
            yield a


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 1
    total = 0
    for path in expand(argv):
        try:
            hits, denials, unavailable, calls = scan_file(path)
        except OSError as e:
            print(f"{path}: {e}", file=sys.stderr)
            return 1
        print(f"{path}: {calls} tool calls, {len(hits)} hits, {denials} auto mode denials, "
              f"{unavailable} classifier-unavailable")
        for lineno, name, label, snip in hits:
            print(f"  line {lineno:<6} [{name}] {label}: {snip}")
        total += len(hits)
    return 2 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
