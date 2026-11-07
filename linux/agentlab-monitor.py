#!/usr/bin/env python3
"""agentlab-monitor: watch a Claude Code run as it happens.

Reads JSON lines on stdin, writes each line unchanged to --out as it arrives,
prints a compact view to the terminal, and stops the run (exits non-zero,
which closes the pipe) when:

  - the init message reports a permission mode other than "auto", or none
  - a prompt in the transcript records a permission mode other than "auto"
  - auto mode denies too many tool calls in a row, or in total

Headless runs feed it stream-json, whose init message carries the mode.
Interactive runs feed it the session transcript Claude Code writes (--session),
where each prompt carries the mode in force when it was sent; agentlab-run
ends the session when the monitor stops.

Exit codes: 0 finished, 3 not in auto mode, 4 denial budget spent,
5 no init message seen, 6 auto mode not confirmed (an init message with no
permissionMode, or with --session, no prompt that records one), 7 input it
won't trust (a record over --max-line-bytes, more than --max-total-bytes in
all, or with --session, a line that isn't a transcript record or isn't valid
UTF-8), 8 nothing arrived for --stall seconds.

With --session, the watcher agentlab-run starts on the sandbox sends a
heartbeat line after each pass over the transcripts (about once a second),
which is skipped (not copied to --out) but counts toward --max-total-bytes.
With --session, --stall times the gap between heartbeats, not between lines, so
a watcher that freezes, or is held on one file, stops the run. The agent owns
that watcher, which makes itself undumpable so its output can't be opened
through /proc; a heartbeat is still a claim from the agent's side, not proof. The watcher sends only
finished records, so a line cut off by the end of the feed (the gateway or the
connection ending it) is kept in --out but not read, and doesn't stop the run.

The monitor reads input the agent can shape, and with --session a file the
agent can write, so a record it can't parse never ends its loop: the raw bytes
still go to --out, and the line is reported, or with --session, stops the run.

A denial is counted from the record's own fields when it has them (session
transcripts mark one with toolDenialKind and permissionDecision), and otherwise
from its text. Neither is documented; both are what Claude Code 2.1.319 wrote.
Check them against the first real transcript and adjust --deny-pattern if needed.
"""
import argparse
import json
import re
import signal
import sys
import time

DEFAULT_DENY = (r"(?i)(blocked by (the )?(auto[- ]mode )?classifier|"
                r"auto[- ]mode (has )?(denied|blocked)|"
                r"permission to use \S{1,64} (has been|was) denied|"
                r"denied by (the )?(claude code )?(auto[- ]mode|permission) classifier)")
DEFAULT_UNAVAILABLE = r"(?i)temporarily unavailable, so auto mode cannot determine"
HEARTBEAT = b'{"agentlab": "heartbeat"}\n'   # what agentlab-run's session watcher sends


class Stalled(Exception):
    pass


def on_alarm(signum, frame):
    raise Stalled()


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
    inp = block.get("input")
    if isinstance(inp, dict):
        for key in ("command", "file_path", "path", "pattern", "url", "query"):
            if key in inp:
                return f"{name}: {short(inp[key], 140)}"
    return f"{name}: {short(json.dumps(inp), 140)}"


def classifier_denied(msg):
    """True when a record marks an auto mode classifier denial in its own fields."""
    if msg.get("toolDenialKind") == "automode-blocked":
        return True
    decision = msg.get("permissionDecision")
    return (isinstance(decision, dict) and decision.get("decision") == "reject"
            and decision.get("reasonType") == "classifier")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True,
                    help="file to append the raw input to, byte for byte (with --session, "
                         "less the watcher's heartbeats)")
    ap.add_argument("--max-consecutive-denials", type=int, default=3)
    ap.add_argument("--max-denials", type=int, default=20)
    ap.add_argument("--deny-pattern", default=DEFAULT_DENY)
    ap.add_argument("--unavailable-pattern", default=DEFAULT_UNAVAILABLE)
    ap.add_argument("--require-init", action="store_true",
                    help="fail (exit 5) if the stream ends with no init message")
    ap.add_argument("--session", action="store_true",
                    help="input is a Claude Code session transcript (an interactive run): "
                         "fail (exit 6) at the end if no prompt confirmed auto mode")
    ap.add_argument("--max-line-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--max-total-bytes", type=int, default=1024 * 1024 * 1024)
    ap.add_argument("--stall", type=int, default=0,
                    help="stop (exit 8) if no heartbeat (with --session) or no line (without) "
                         "arrives for this many seconds; 0, the default, waits forever")
    ap.add_argument("--log", help="write the view to this file instead of the terminal")
    ap.add_argument("--quiet", action="store_true", help="no terminal view")
    args = ap.parse_args()
    if args.stall < 0:
        ap.error("--stall must be 0 or more")

    deny_re = re.compile(args.deny_pattern)
    unavail_re = re.compile(args.unavailable_pattern)
    state = {"denials": 0, "consecutive": 0, "unavailable": 0, "tool_calls": 0,
             "turn": 0, "saw_init": False, "confirmed": False}
    log = open(args.log, "a", encoding="utf-8") if args.log else None

    def show(msg):
        text = printable(msg)
        if log:
            log.write(time.strftime("%Y-%m-%dT%H:%M:%S%z ") + text + "\n")
            log.flush()
        elif not args.quiet:
            print(text, flush=True)

    def handle(msg):
        """Act on one record. Returns an exit code to stop with, or None."""
        mtype = msg.get("type")

        if mtype == "system" and msg.get("subtype") == "init":
            if args.session:
                show("  ! STOP: an init record in a session transcript, which Claude Code doesn't write there")
                return 7
            state["saw_init"] = True
            mode = msg.get("permissionMode")
            rc = 6 if mode is None else 3 if mode != "auto" else None   # decide before printing
            state["confirmed"] = rc is None
            show(f"[init] model={msg.get('model', '?')} permissionMode={mode or '?'} "
                 f"cwd={msg.get('cwd', '?')}")
            if rc == 6:
                show("  ! STOP: init message has no permissionMode field, so auto mode can't be confirmed")
            elif rc == 3:
                show(f"  ! STOP: permission mode is '{mode}', not 'auto'")
            return rc

        # Prompts in a session transcript record the mode they were sent in.
        if mtype == "user" and "permissionMode" in msg:
            mode = msg.get("permissionMode")
            if mode != "auto":
                show(f"  ! STOP: a prompt was sent in permission mode '{mode}', not 'auto'")
                return 3
            state["confirmed"] = True

        body = msg.get("message")
        content = body.get("content") if isinstance(body, dict) else None
        if not isinstance(content, list):
            content = []

        if mtype == "assistant":
            state["turn"] += 1
            turn = state["turn"]
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    state["tool_calls"] += 1
                    show(f"[{turn:>3}] {describe_tool(block)}")
                elif block.get("type") == "text":
                    text = block.get("text")
                    if isinstance(text, str) and text.strip():
                        show(f"[{turn:>3}] says: {short(text, 160)}")

        elif mtype == "user":
            marked = classifier_denied(msg)   # the record's own fields win over its text
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                text = text_of(block.get("content"))
                is_error = bool(block.get("is_error"))
                if is_error and marked:
                    denied = True
                elif unavail_re.search(text):
                    state["unavailable"] += 1
                    show(f"      ~ classifier unavailable ({state['unavailable']})")
                    continue
                else:
                    denied = is_error and bool(deny_re.search(text))
                if denied:
                    state["denials"] += 1
                    state["consecutive"] += 1
                    show(f"      ! DENIED ({state['consecutive']} in a row, {state['denials']} total): "
                         f"{short(text, 140)}")
                    if (state["consecutive"] >= args.max_consecutive_denials
                            or state["denials"] >= args.max_denials):
                        show(f"  ! STOP: denial budget spent ({state['consecutive']} in a row, "
                             f"{state['denials']} total). Read the transcript, then start a fresh run. "
                             "Don't resume this one.")
                        return 4
                else:
                    state["consecutive"] = 0
                    if is_error:
                        show(f"      x error: {short(text, 140)}")

        elif mtype == "result":
            show(f"[done] {msg.get('subtype', '?')} after {msg.get('num_turns', '?')} turns, "
                 f"{state['tool_calls']} tool calls, {state['denials']} denials, "
                 f"{state['unavailable']} unavailable")
        return None

    stdin = sys.stdin.buffer

    deadline = [time.monotonic() + args.stall]   # when --stall runs out

    def next_line():
        if not args.stall:
            return stdin.readline(args.max_line_bytes + 1)
        left = deadline[0] - time.monotonic()
        if left <= 0:
            raise Stalled()
        signal.setitimer(signal.ITIMER_REAL, left)   # a stalled read raises Stalled
        try:
            return stdin.readline(args.max_line_bytes + 1)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    if args.stall:
        signal.signal(signal.SIGALRM, on_alarm)
    total = 0
    lineno = 0
    heard = {"record": None, "heartbeat": None}   # when each last arrived

    def when(t):
        return time.strftime("%H:%M:%S", time.localtime(t)) if t else "never"

    with open(args.out, "ab") as out:
        while True:
            try:
                raw = next_line()
            except Stalled:
                show(f"  ! STOP: no {'heartbeat' if args.session else 'line'} for {args.stall} seconds, "
                     "so nothing is watching "
                     f"(last record {when(heard['record'])}, last heartbeat {when(heard['heartbeat'])}, "
                     f"{lineno} records)")
                return 8
            if not raw:
                break
            if args.session and raw == HEARTBEAT:
                heard["heartbeat"] = time.time()
                deadline[0] = time.monotonic() + args.stall
                total += len(raw)
                if total > args.max_total_bytes:
                    show(f"  ! STOP: input passed {args.max_total_bytes} bytes")
                    return 7
                continue
            heard["record"] = time.time()
            if not args.session:
                deadline[0] = time.monotonic() + args.stall
            out.write(raw)
            out.flush()
            lineno += 1
            total += len(raw)
            if total > args.max_total_bytes:
                show(f"  ! STOP: input passed {args.max_total_bytes} bytes")
                return 7
            if len(raw) > args.max_line_bytes:
                show(f"  ! STOP: line {lineno} is longer than {args.max_line_bytes} bytes")
                return 7
            if args.session and not raw.endswith(b"\n"):
                show(f"  (line {lineno} was cut off when the feed ended; kept in --out, not read)")
                break
            try:
                # Claude Code writes UTF-8. In a session file the agent can write,
                # a bad byte inside a JSON string would otherwise parse.
                line = raw.decode("utf-8", errors="strict" if args.session else "replace").strip()
            except UnicodeDecodeError:
                show(f"  ! STOP: line {lineno} isn't valid UTF-8")
                return 7
            if not line:
                continue
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):
                msg = None
            if not isinstance(msg, dict):
                if args.session:
                    show(f"  ! STOP: line {lineno} isn't a transcript record: {short(line, 120)}")
                    return 7
                show(f"  (non-JSON) {short(line, 160)}")
                continue
            try:
                rc = handle(msg)
            except Exception as e:  # a shape this monitor didn't expect must not end its loop
                if args.session:
                    show(f"  ! STOP: line {lineno} is a record this monitor can't read ({type(e).__name__})")
                    return 7
                show(f"  ! couldn't read line {lineno} ({type(e).__name__}); carrying on")
                continue
            if rc is not None:
                return rc

    if args.require_init and not state["saw_init"]:
        show("  ! stream ended without an init message")
        return 5
    if args.session and not state["confirmed"]:
        show("  ! no prompt in the session transcript confirmed auto mode")
        return 6
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(1)
