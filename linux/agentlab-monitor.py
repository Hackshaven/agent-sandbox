#!/usr/bin/env python3
"""agentlab-monitor: watch a Claude Code stream-json run as it happens.

Reads stream-json lines on stdin, writes each line unchanged to --out as it
arrives, prints a compact view to the terminal, and stops the run (exits
non-zero, which closes the pipe) when:

  - the init message reports a permission mode other than "auto"
  - auto mode denies too many tool calls in a row, or in total

Exit codes: 0 finished, 3 not in auto mode, 4 denial budget spent,
5 no init message seen.

The denial text Claude Code uses isn't documented here, so the patterns are a
best guess. Check them against the first real denial you see in a transcript
and adjust --deny-pattern if needed.
"""
import argparse
import json
import re
import sys

DEFAULT_DENY = (r"(?i)(blocked by (the )?(auto[- ]mode )?classifier|"
                r"auto[- ]mode (has )?(denied|blocked)|"
                r"permission to use \S+ (has been|was) denied|"
                r"denied by (the )?(auto[- ]mode|permission) classifier)")
DEFAULT_UNAVAILABLE = r"(?i)temporarily unavailable, so auto mode cannot determine"


def text_of(content):
    """Flatten tool_result content (str or list of blocks) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return ""


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


def short(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def describe_tool(block):
    name = block.get("name", "?")
    inp = block.get("input") or {}
    for key in ("command", "file_path", "path", "pattern", "url", "query"):
        if key in inp:
            return f"{name}: {short(inp[key], 140)}"
    return f"{name}: {short(json.dumps(inp), 140)}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="file to write the raw stream to")
    ap.add_argument("--max-consecutive-denials", type=int, default=3)
    ap.add_argument("--max-denials", type=int, default=20)
    ap.add_argument("--deny-pattern", default=DEFAULT_DENY)
    ap.add_argument("--unavailable-pattern", default=DEFAULT_UNAVAILABLE)
    ap.add_argument("--require-init", action="store_true",
                    help="fail (exit 5) if the stream ends with no init message")
    ap.add_argument("--quiet", action="store_true", help="no terminal view")
    args = ap.parse_args()

    deny_re = re.compile(args.deny_pattern)
    unavail_re = re.compile(args.unavailable_pattern)
    denials = consecutive = unavailable = tool_calls = 0
    saw_init = False
    turn = 0

    def show(msg):
        if not args.quiet:
            print(printable(msg), flush=True)

    with open(args.out, "a", encoding="utf-8") as out:
        for raw in sys.stdin:
            out.write(raw)
            out.flush()
            line = raw.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                show(f"  (non-JSON) {short(line, 160)}")
                continue
            if not isinstance(msg, dict):
                continue
            mtype = msg.get("type")

            if mtype == "system" and msg.get("subtype") == "init":
                saw_init = True
                mode = msg.get("permissionMode")
                show(f"[init] model={msg.get('model', '?')} permissionMode={mode or '?'} "
                     f"cwd={msg.get('cwd', '?')}")
                if mode is None:
                    show("  ! init message has no permissionMode field; can't confirm auto mode")
                elif mode != "auto":
                    show(f"  ! STOP: permission mode is '{mode}', not 'auto'")
                    return 3
                continue

            body = msg.get("message") or {}
            content = body.get("content") if isinstance(body, dict) else None
            if not isinstance(content, list):
                content = []

            if mtype == "assistant":
                turn += 1
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use":
                        tool_calls += 1
                        show(f"[{turn:>3}] {describe_tool(block)}")
                    elif block.get("type") == "text" and block.get("text", "").strip():
                        show(f"[{turn:>3}] says: {short(block['text'], 160)}")

            elif mtype == "user":
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    text = text_of(block.get("content"))
                    if unavail_re.search(text):
                        unavailable += 1
                        show(f"      ~ classifier unavailable ({unavailable})")
                    elif block.get("is_error") and deny_re.search(text):
                        denials += 1
                        consecutive += 1
                        show(f"      ! DENIED ({consecutive} in a row, {denials} total): {short(text, 140)}")
                        if consecutive >= args.max_consecutive_denials or denials >= args.max_denials:
                            show(f"  ! STOP: denial budget spent ({consecutive} in a row, {denials} total). "
                                 "Read the transcript, then start a fresh run. Don't resume this one.")
                            return 4
                    else:
                        consecutive = 0
                        if block.get("is_error"):
                            show(f"      x error: {short(text, 140)}")

            elif mtype == "result":
                show(f"[done] {msg.get('subtype', '?')} after {msg.get('num_turns', '?')} turns, "
                     f"{tool_calls} tool calls, {denials} denials, {unavailable} unavailable")

    if args.require_init and not saw_init:
        show("  ! stream ended without an init message")
        return 5
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(1)
