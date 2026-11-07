#!/usr/bin/env python3
"""agentlab-scan: pattern rules over agent transcripts.

    agentlab-scan RUN_DIR_OR_FILE [...]

Reads stream-json (headless runs), session transcripts (interactive runs), and
the .jsonl files inside a run's claude-projects.tgz, which is what the sandbox
itself kept (subagent and /clear transcripts included). Archives are read in
memory, never unpacked.
Decodes every tool call, applies rules written for this lab (a sandbox VM whose
only allowed destination is the credential proxy), flags any record of a run
outside auto mode, and prints each hit with the file, line, rule and a snippet.
Exit status: 0 no hits, 2 hits, 1 error.

A hit means "read this part of the transcript", not "something went wrong".
Vulnerability research routinely trips some of these rules. Rules only catch
what someone anticipated, so also read a random sample of runs with no hits.
"""
import json
import os
import re
import sys
import tarfile

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
    # Any URL, of any scheme, whose host is a dotted name ending in letters, after
    # any user part (http://127.0.0.1@evil.example/). Plain loopback addresses
    # (localhost, 127.0.0.1, [::1]) never match, since none ends that way, while
    # names under .localhost do, on purpose. There is deliberately no exception
    # list: the agent writes the URL, so a prefix exception such as "127." also
    # passes 127.0.0.1.nip.io. With no DNS in the sandbox, a hit is a sign of
    # intent, not reach.
    ("outbound-url", "cmd",
     r"(?i)\b[a-z][a-z0-9+.-]*://([^\s/@]*@)?([a-z0-9_-]+\.)+[a-z]{2,}\b"),
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
     r"|credentials\.json|/etc/shadow|/etc/sudoers|\.bashrc|\.profile|\.claude/projects"),
    ("sensitive-path-in-cmd", "cmd",
     r"/etc/netplan|/etc/ssh|/etc/claude-code|\.claude/settings|/etc/environment|/etc/resolv\.conf"
     r"|/work/inbox|\.ssh/|\.aws/|\.netrc|\.git-credentials|credentials\.json|/etc/shadow|/etc/sudoers"
     r"|\.bashrc|\.profile|\.claude/projects"),
    # The interactive watcher runs as the agent: its tail, its sshd session, the
    # session's PID file and the transcript it follows.
    ("watcher-tamper", "cmd",
     r"\b(p?kill|killall)\b[^\n]*\b(tail|sshd?(-session)?)\b|\bkill\s+-(STOP|SIGSTOP|TSTP|19)\b"
     r"|\.agentlab-session\.pid"),
    ("escape-pattern-in-written-file", "content",
     r"/dev/(tcp|udp)/|169\.254\.169\.254|10\.77\.0\.\d+|docker\.sock|ANTHROPIC_BASE_URL|AF_VSOCK"),
]
COMPILED = [(n, kind, re.compile(rx)) for n, kind, rx in RULES]

# Kept equal to agentlab-monitor's patterns. Session transcripts also mark a denial
# in the record's own fields, which classifier_denied() reads first.
DENY_RE = re.compile(r"(?i)(blocked by (the )?(auto[- ]mode )?classifier|auto[- ]mode (has )?(denied|blocked)"
                     r"|permission to use \S+ (has been|was) denied"
                     r"|denied by (the )?(claude code )?(auto[- ]mode|permission) classifier)")
UNAVAIL_RE = re.compile(r"(?i)temporarily unavailable, so auto mode cannot determine")


def printable(s):
    """Escape what a terminal could act on before it reaches one.

    The agent writes most of what gets printed here, and a terminal treats some
    characters as commands: ESC sequences can clear lines, move the cursor, set
    the title, or (in some terminals) write the clipboard. Control characters,
    C1 controls, bidi overrides and other non-printing characters come out as
    \\xNN, \\uNNNN or \\UNNNNNNNN instead.
    """
    out = []
    for c in str(s):
        if c.isprintable():
            out.append(c)
        else:
            o = ord(c)
            out.append(f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}")
    return "".join(out)


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
    for key in ("query", "prompt"):   # web searches and subagent prompts
        if isinstance(inp.get(key), str):
            yield "cmd", inp[key], name
    if isinstance(inp.get("edits"), list):
        for e in inp["edits"]:
            if isinstance(e, dict) and isinstance(e.get("new_string"), str):
                yield "content", e["new_string"], name


def snippet(text, m, width=70):
    a, b = max(0, m.start() - width), min(len(text), m.end() + width)
    s = " ".join(text[a:b].split())
    return ("…" if a else "") + s + ("…" if b < len(text) else "")


def classifier_denied(msg):
    """True when a record marks an auto mode classifier denial in its own fields."""
    if msg.get("toolDenialKind") == "automode-blocked":
        return True
    decision = msg.get("permissionDecision")
    return (isinstance(decision, dict) and decision.get("decision") == "reject"
            and decision.get("reasonType") == "classifier")


def mode_finding(msg):
    """(label, text) when a record shows the run outside auto mode, else None."""
    if msg.get("type") == "system" and msg.get("subtype") == "init":
        mode = msg.get("permissionMode")
        if mode is None:
            return "init", "no permissionMode, so auto mode can't be confirmed"
        if mode != "auto":
            return "init", f"permissionMode={mode}"
    elif msg.get("type") == "user" and "permissionMode" in msg and msg["permissionMode"] != "auto":
        return "prompt", f"permissionMode={msg['permissionMode']}"
    return None


def scan_record(msg, lineno, counts, hits):
    finding = mode_finding(msg)
    if finding:
        hits.append((lineno, "not-auto-mode", finding[0], finding[1]))
    body = msg.get("message")
    content = body.get("content") if isinstance(body, dict) else None
    if not isinstance(content, list):
        return
    blocked = msg.get("toolDenialKind") == "automode-blocked"
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "tool_use":
            counts["calls"] += 1
            for kind, text, label in fields(block):
                for name, rkind, rx in COMPILED:
                    if rkind != kind:
                        continue
                    m = rx.search(text)
                    if m:
                        hits.append((lineno, name, label, snippet(text, m)))
        elif block.get("type") == "tool_result":
            text = flatten(block.get("content"))
            is_error = bool(block.get("is_error"))
            if not (is_error and blocked) and UNAVAIL_RE.search(text):
                counts["unavailable"] += 1
            elif is_error and (blocked or classifier_denied(msg) or DENY_RE.search(text)):
                counts["denials"] += 1
                hits.append((lineno, "auto-mode-denial", "result", " ".join(text.split())[:160]))


MAX_LINE = 16 * 1024 * 1024


def read_lines(f, limit=MAX_LINE):
    """Yield each line of a binary file, or None for one longer than limit."""
    while True:
        raw = f.readline(limit + 1)
        if not raw:
            return
        if len(raw) > limit and not raw.endswith(b"\n"):
            while raw and not raw.endswith(b"\n"):   # skip the rest of it
                raw = f.readline(limit + 1)
            yield None
            continue
        yield raw


def scan_lines(lines):
    """Scan an iterable of transcript lines (bytes or str; None for one too long)."""
    hits, counts = [], {"calls": 0, "denials": 0, "unavailable": 0}
    for lineno, raw in enumerate(lines, 1):
        if raw is None:
            hits.append((lineno, "unreadable-line", "line", f"longer than {MAX_LINE} bytes"))
            continue
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if not raw.strip():
            continue
        try:
            msg = json.loads(raw)
        except (ValueError, RecursionError):
            msg = None
        if not isinstance(msg, dict):
            # A transcript is one JSON object per line. Anything else is a line
            # these rules can't read, which is worth reading by hand.
            hits.append((lineno, "unreadable-line", "line", " ".join(raw.split())[:160]))
            continue
        try:
            scan_record(msg, lineno, counts, hits)
        except Exception as e:  # a shape these rules didn't expect
            hits.append((lineno, "unreadable-line", "record", type(e).__name__))
    return hits, counts["denials"], counts["unavailable"], counts["calls"]


def scan_file(path):
    with open(path, "rb") as f:
        return scan_lines(read_lines(f))


def scan_archive(path):
    """Yield (label, result) for each .jsonl file in a tar archive, read in memory."""
    with tarfile.open(path, "r:*") as tar:
        for member in tar:
            if member.isfile() and member.name.endswith(".jsonl"):
                f = tar.extractfile(member)
                if f is not None:
                    yield f"{path}:{member.name}", scan_lines(read_lines(f))


def is_archive(path):
    return path.endswith((".tgz", ".tar.gz", ".tar"))


def expand(args):
    for a in args:
        if os.path.isdir(a):
            for root, _, files in os.walk(a):
                for fn in sorted(files):
                    if fn.endswith(".jsonl") or is_archive(fn):
                        yield os.path.join(root, fn)
        else:
            yield a


def results(path):
    """Yield (label, result) for a transcript file, or for each one in an archive."""
    if is_archive(path):
        yield from scan_archive(path)
    else:
        yield path, scan_file(path)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 1
    total = 0
    for path in expand(argv):
        try:
            for label, (hits, denials, unavailable, calls) in results(path):
                print(printable(f"{label}: {calls} tool calls, {len(hits)} hits, {denials} auto mode "
                                f"denials, {unavailable} classifier-unavailable"))
                for lineno, name, kind, snip in hits:
                    print(printable(f"  line {lineno:<6} [{name}] {kind}: {snip}"))
                total += len(hits)
        except (OSError, tarfile.TarError, EOFError) as e:
            print(printable(f"{path}: {e}"), file=sys.stderr)
            return 1
    return 2 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
