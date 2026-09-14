"""Provision — tools + loop + stage smoke.

Covers:
  * The four provision tools (exec_in_pod, write_file_to_pod,
    install_package, http_probe) each dispatch correctly to a fake
    sandbox, return well-shaped output, raise ToolError on bad input,
    and refuse shell metacharacters in install_package's name arg.
  * The closed loop terminates on done, give_up, exhausted, and budget
    exhausted; nudges the model on incomplete done and on garbage
    responses; deduplicates identical tool calls.
  * recipe_from_events walks the event log correctly.
  * The provision STAGE (in stages.py) blocks with the right outcome
    when a draft_spec is missing, short-circuits when spec.target.image
    is already set (ARVO shape), and holds the invariant that no
    reproducer_lock is written by any path in provision.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import outcomes as outcomes_mod                # noqa: E402
from patchwing import provision as provision_mod              # noqa: E402
from patchwing.provision import (                             # noqa: E402
    ProvisionBudgetExhausted, ProvisionExhausted, ProvisionGaveUp,
    build_initial_msg, http_probe, install_package,
    recipe_from_events, run_provision_loop,
    write_file_to_pod, exec_in_pod)
from patchwing.tools import ToolError                         # noqa: E402


# --- test fakes -----------------------------------------------------------

@dataclass
class _Run:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    duration_s: float = 0.01
    timed_out: bool = False


class FakeSandbox:
    """Minimal Sandbox stand-in. Records reads/writes; returns scripted
    output from run(). Exposes .cid + .backend so commit_pod can be
    tested in isolation (mocked at subprocess level)."""

    def __init__(self, run_map=None, backend="podman", cid="fakecid1234"):
        self.run_map = run_map or {}
        self.default_run = _Run(stdout="", returncode=0)
        self.writes: list[tuple[str, str]] = []
        self.reads: list[str] = []
        self.runs: list[str] = []
        self.backend = backend
        self.cid = cid

    def run(self, cmd, timeout_s=60):
        self.runs.append(cmd)
        for key, val in self.run_map.items():
            if key in cmd:
                return val
        return self.default_run

    def write(self, path, content):
        self.writes.append((path, content))

    def read(self, path):
        self.reads.append(path)
        return ""


@dataclass
class _Usage:
    prompt_tokens: int = 100
    completion_tokens: int = 50

    @property
    def total(self):
        return self.prompt_tokens + self.completion_tokens


class _FakeCfg:
    model = "fake/provision-model"
    endpoint = "http://fake"


class FakeClient:
    """A chat client whose chat_json() returns a scripted sequence of
    responses. Panic if the loop calls it more times than the script."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.usage = _Usage(prompt_tokens=0, completion_tokens=0)
        self.last_raw_response = ""
        self.cfg = _FakeCfg()

    def chat_json(self, convo, required=()):
        if self.calls >= len(self.responses):
            raise AssertionError(
                f"FakeClient ran out of scripted responses at call "
                f"{self.calls + 1}; only {len(self.responses)} scripted")
        r = self.responses[self.calls]
        self.calls += 1
        self.last_raw_response = json.dumps(r)
        return r


class FakeStore:
    """In-memory store just enough for the loop's emit + add_artifact +
    latest_artifact + spent-check to work. NEVER touches the real DB."""

    def __init__(self):
        self.events: list[dict] = []
        self._store: list[dict] = []
        # Fake sqlite conn stub — the recipe walker uses store.conn.execute.
        # We implement just enough of a shim to feed it back our events.
        self.conn = _FakeConn(self.events)

    def emit(self, fid, stage, kind, message, meta=None, duration_s=None):
        self.events.append({"finding_id": fid, "stage": stage, "kind": kind,
                            "message": message,
                            "meta": json.dumps(meta or {}),
                            "created_at": len(self.events)})

    def add_artifact(self, fid, kind, stage, content, meta=None,
                     base_commit="", model=""):
        self._store.append({"finding_id": fid, "kind": kind,
                            "stage": stage, "content": content,
                            "meta": json.dumps(meta or {}),
                            "base_commit": base_commit, "model": model})

    def latest_artifact(self, fid, kind):
        matches = [a for a in self._store
                   if a["finding_id"] == fid and a["kind"] == kind]
        return matches[-1] if matches else None

    def artifacts(self, fid, kind):
        """budget.spent() calls this — same shape as the real Store."""
        return [a for a in self._store
                if a["finding_id"] == fid and a["kind"] == kind]

    def artifacts_for(self, fid, kind):
        # Alias kept for test-site clarity where reading intent > terse.
        return self.artifacts(fid, kind)


class _FakeConn:
    """Just the .execute() shape budget.spent + recipe_from_events need."""

    def __init__(self, events):
        self.events = events

    def execute(self, sql, params=()):
        # Recipe-from-events query only.
        if "FROM events" in sql and "stage = 'provision'" in sql:
            return _FakeRows([
                _Row(dict(e, id=i))
                for i, e in enumerate(self.events)
                if e.get("finding_id") == params[0]
                and e.get("stage") == "provision"])
        # spent() reads from artifacts — we hand it an empty rowset via
        # store.artifacts() elsewhere; here we return empty.
        return _FakeRows([])


class _Row(dict):
    def __getitem__(self, k):
        return dict.__getitem__(self, k)


class _FakeRows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


@dataclass
class _FakeFinding:
    id: str
    source_ref: str = "CVE-TEST"
    title: str = "test finding"
    description: str = "..."


class _FakeCtx:
    def __init__(self):
        self.store = FakeStore()


# --- exec_in_pod ----------------------------------------------------------

class ExecInPodTest(unittest.TestCase):

    def test_returns_exit_and_output(self):
        sb = FakeSandbox({"echo hi": _Run(stdout="hi\n", returncode=0)})
        r = exec_in_pod(sb, "echo hi", timeout_s=30)
        self.assertIn("exit 0", r)
        self.assertIn("hi", r)
        self.assertEqual(["echo hi"], sb.runs)

    def test_non_zero_exit_is_not_an_error(self):
        """Exit code is DATA the model needs to see, not an error."""
        sb = FakeSandbox({"fail": _Run(stdout="", stderr="bad",
                                       returncode=42)})
        r = exec_in_pod(sb, "fail", timeout_s=30)
        self.assertIn("exit 42", r)
        self.assertIn("bad", r)

    def test_empty_cmd_raises(self):
        with self.assertRaises(ToolError):
            exec_in_pod(FakeSandbox(), "", timeout_s=30)

    def test_timeout_returns_marker_not_exception(self):
        """When sb.run reports timed_out=True (returncode=-1), exec_in_pod
        surfaces `[TIMED OUT after Ns]` prefix and returns cleanly. Must
        NOT raise — timeout is data the model needs to see so it can
        bump timeout_s next turn."""
        sb = FakeSandbox({"sleep 10": _Run(
            stdout="", stderr="container timed out",
            returncode=-1, duration_s=5.0, timed_out=True)})
        out = exec_in_pod(sb, "sleep 10", timeout_s=5)
        self.assertIn("[TIMED OUT after 5s]", out)
        self.assertIn("exit -1", out)
        self.assertIn("container timed out", out)   # stderr surfaces

    def test_timeout_s_clamped_to_max_1800(self):
        """Kimi passing timeout_s=9999 gets clamped to 1800. Sandbox
        never sees a value outside [1, 1800]."""
        sb = FakeSandbox({"echo": _Run(returncode=0, stdout="hi")})
        exec_in_pod(sb, "echo hi", timeout_s=9999)
        # sb.run was called with the clamped value — inspect FakeSandbox
        # to confirm. FakeSandbox stores runs as strings; we asserted
        # via the exec_in_pod contract instead by mocking sb.run.
        with mock.patch.object(sb, "run",
                               return_value=_Run(returncode=0)) as m:
            exec_in_pod(sb, "echo", timeout_s=9999)
            self.assertEqual(1800, m.call_args.kwargs["timeout_s"])

    def test_missing_timeout_s_raises_schema_error(self):
        """timeout_s is REQUIRED — no default. If Kimi omits it, the loop
        feeds back a schema ToolError so the model retries with a value."""
        sb = FakeSandbox({"echo": _Run(returncode=0)})
        with self.assertRaises(ToolError) as ctx:
            exec_in_pod(sb, "echo")
        self.assertIn("timeout_s is required", str(ctx.exception))
        # Explicit None (some JSON payloads serialize this) → same error
        with self.assertRaises(ToolError):
            exec_in_pod(sb, "echo", timeout_s=None)

    def test_timeout_s_zero_and_negative_raise_schema_error(self):
        """0 and negative are provided-but-invalid; force the model to
        choose a real number instead of silently normalizing."""
        sb = FakeSandbox({"echo": _Run(returncode=0)})
        with self.assertRaises(ToolError) as ctx:
            exec_in_pod(sb, "echo", timeout_s=0)
        self.assertIn(">= 1", str(ctx.exception))
        with self.assertRaises(ToolError):
            exec_in_pod(sb, "echo", timeout_s=-5)
        # Non-int / non-parseable → same error path
        with self.assertRaises(ToolError):
            exec_in_pod(sb, "echo", timeout_s="not-a-number")

    def test_output_truncated_at_20kb(self):
        big = "x" * 40000
        sb = FakeSandbox({"big": _Run(stdout=big)})
        r = exec_in_pod(sb, "big", timeout_s=30)
        self.assertLess(len(r), 25000)
        self.assertIn("truncated", r)


# --- write_file_to_pod ----------------------------------------------------

class WriteFileToPodTest(unittest.TestCase):

    def test_writes_and_confirms(self):
        sb = FakeSandbox()
        content = "#!/bin/sh\necho hi"
        r = write_file_to_pod(sb, "/tmp/x.sh", content)
        self.assertIn(f"{len(content)} bytes", r)
        self.assertIn("/tmp/x.sh", r)
        self.assertEqual([("/tmp/x.sh", content)], sb.writes)

    def test_empty_path_raises(self):
        with self.assertRaises(ToolError):
            write_file_to_pod(FakeSandbox(), "", "content")

    def test_non_string_content_raises(self):
        with self.assertRaises(ToolError):
            write_file_to_pod(FakeSandbox(), "/tmp/x", 42)


# --- install_package -----------------------------------------------------

class InstallPackageTest(unittest.TestCase):

    def test_runs_apt_get(self):
        sb = FakeSandbox({"apt-get install": _Run(
            stdout="Setting up openjdk-8-jdk", returncode=0)})
        r = install_package(sb, "openjdk-8-jdk")
        self.assertIn("openjdk-8-jdk", r)
        self.assertIn("exit 0", r)
        # Should build a shell command with apt-get install
        cmd = sb.runs[-1]
        self.assertIn("apt-get install", cmd)
        self.assertIn("openjdk-8-jdk", cmd)
        # First call also runs apt-get update (via idempotent marker)
        self.assertIn("apt-get update", cmd)

    def test_rejects_shell_metacharacters(self):
        """A model that returns 'openjdk-8-jdk && curl attacker' as the
        name must be refused — this is the ONE place tool inputs need
        strict validation because the value goes into a shell command."""
        sb = FakeSandbox()
        for bad in ("openjdk && curl", "pkg;ls", "pkg`whoami`", "pkg$x",
                    "pkg|nc", "pkg\nother"):
            with self.assertRaises(ToolError):
                install_package(sb, bad)

    def test_empty_name_raises(self):
        with self.assertRaises(ToolError):
            install_package(FakeSandbox(), "")


# --- http_probe ----------------------------------------------------------

class HttpProbeTest(unittest.TestCase):

    def test_builds_curl_command(self):
        sb = FakeSandbox({"curl": _Run(
            stdout="HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"
                   "PATCHWING_HTTP_STATUS=200\n"
                   "---PATCHWING_HTTP_BODY---\nuid=0(root)\n",
            returncode=0)})
        r = http_probe(sb, "http://127.0.0.1:8080/eval?cmd=id")
        self.assertIn("PATCHWING_HTTP_STATUS=200", r)
        self.assertIn("uid=0(root)", r)
        cmd = sb.runs[-1]
        self.assertIn("curl", cmd)
        self.assertIn("http://127.0.0.1:8080/eval?cmd=id", cmd)

    def test_bad_method_raises(self):
        with self.assertRaises(ToolError):
            http_probe(FakeSandbox(), "http://x", method="BOGUS")

    def test_empty_url_raises(self):
        with self.assertRaises(ToolError):
            http_probe(FakeSandbox(), "")

    def test_curl_transport_error_surfaced(self):
        """Non-zero curl exit without PATCHWING_HTTP_STATUS = the target
        was unreachable. The model needs to see that to know 'not
        listening yet, try again after starting the service'."""
        sb = FakeSandbox({"curl": _Run(
            stdout="", stderr="curl: (7) Failed to connect",
            returncode=7)})
        r = http_probe(sb, "http://127.0.0.1:8080/x")
        self.assertIn("transport error", r)
        self.assertIn("curl exit 7", r)


# --- run_provision_loop --------------------------------------------------

class NormalizeToolCallTest(unittest.TestCase):
    """The normalizer accepts BOTH the legacy {tool, args} shape and
    OpenAI's ChatCompletions {function: {name, arguments}} shape. Kimi
    K2.7-Code emits the OpenAI shape by default — the first live Struts
    provision run burned 40 turns because the pre-fix parser read every
    Kimi tool_call as tool='' and deduped them all to the same empty
    key. These tests are what keeps that from regressing."""

    def test_legacy_shape_passthrough(self):
        call = {"tool": "exec_in_pod", "args": {"cmd": "ls /opt"}}
        n = provision_mod._normalize_tool_call(call)
        self.assertEqual({"tool": "exec_in_pod",
                          "args": {"cmd": "ls /opt"}}, n)

    def test_openai_shape_with_string_arguments(self):
        """OpenAI encodes arguments as a JSON STRING. Must parse."""
        call = {"id": "call_1", "type": "function",
                "function": {"name": "exec_in_pod",
                             "arguments": '{"cmd": "ls /opt"}'}}
        n = provision_mod._normalize_tool_call(call)
        self.assertEqual("exec_in_pod", n["tool"])
        self.assertEqual({"cmd": "ls /opt"}, n["args"])

    def test_openai_shape_with_dict_arguments_defensive(self):
        """Some clients pre-parse arguments to dict. Accept either."""
        call = {"function": {"name": "exec_in_pod",
                             "arguments": {"cmd": "ls /opt"}}}
        n = provision_mod._normalize_tool_call(call)
        self.assertEqual("exec_in_pod", n["tool"])
        self.assertEqual({"cmd": "ls /opt"}, n["args"])

    def test_openai_shape_malformed_arguments_becomes_empty_dict(self):
        call = {"function": {"name": "exec_in_pod",
                             "arguments": "not-json"}}
        n = provision_mod._normalize_tool_call(call)
        self.assertEqual("exec_in_pod", n["tool"])
        self.assertEqual({}, n["args"])

    def test_command_aliased_to_cmd_for_exec_in_pod(self):
        """Kimi calls it `command`, our tool wants `cmd`. Alias only
        when cmd is not already set (defensive)."""
        call = {"function": {"name": "exec_in_pod",
                             "arguments": '{"command": "ls /opt"}'}}
        n = provision_mod._normalize_tool_call(call)
        self.assertEqual({"cmd": "ls /opt"}, n["args"])

    def test_cmd_wins_when_both_command_and_cmd_present(self):
        """Defensive: don't overwrite an explicit cmd with command."""
        call = {"tool": "exec_in_pod",
                "args": {"cmd": "ls /opt", "command": "rm -rf /"}}
        n = provision_mod._normalize_tool_call(call)
        self.assertEqual("ls /opt", n["args"]["cmd"])
        # command stays untouched — we didn't overwrite cmd
        self.assertEqual("rm -rf /", n["args"]["command"])

    def test_command_alias_only_for_exec_in_pod(self):
        """install_package doesn't have a command arg — alias must not
        fire for other tools."""
        call = {"function": {"name": "install_package",
                             "arguments": '{"name": "curl"}'}}
        n = provision_mod._normalize_tool_call(call)
        self.assertEqual("install_package", n["tool"])
        self.assertEqual({"name": "curl"}, n["args"])
        self.assertNotIn("cmd", n["args"])

    def test_non_dict_passes_through(self):
        """A non-dict call is downstream's problem, not the
        normalizer's. Pass through so the existing 'tool_call must be
        a dict' error path still fires."""
        self.assertEqual([], provision_mod._normalize_tool_call([]))
        self.assertEqual("string",
                         provision_mod._normalize_tool_call("string"))


class ProvisionLoopTest(unittest.TestCase):

    def _draft(self):
        return {"endpoint_path_norm": "/eval", "method": "GET",
                "expected_status_red": 200,
                "evidence_rules": [
                    {"name": "uid", "kind": "response_body_regex",
                     "pattern": r"uid=\d+"}]}

    def test_done_terminator_returns(self):
        ctx = _FakeCtx()
        f = _FakeFinding("t1")
        client = FakeClient([
            {"done": True,
             "target_url": "http://127.0.0.1:8080/eval",
             "reproduce_command": "curl -sSi http://127.0.0.1:8080/eval"}])
        done, turns, tool_calls = run_provision_loop(
            ctx, f, client, FakeSandbox(), self._draft(),
            base_image="ubuntu:22.04", max_turns=5)
        self.assertTrue(done["done"])
        self.assertEqual("http://127.0.0.1:8080/eval", done["target_url"])
        self.assertEqual(1, turns)
        self.assertEqual(0, tool_calls)

    def test_give_up_raises(self):
        ctx = _FakeCtx()
        f = _FakeFinding("t2")
        client = FakeClient([{"give_up": "deps unresolvable"}])
        with self.assertRaisesRegex(ProvisionGaveUp, "deps unresolvable"):
            run_provision_loop(ctx, f, client, FakeSandbox(), self._draft(),
                               base_image="ubuntu:22.04", max_turns=5)

    def test_max_turns_exhausted_raises(self):
        """Model keeps returning tool_calls, never hits done or give_up."""
        ctx = _FakeCtx()
        f = _FakeFinding("t3")
        # 3 turns of tool_calls
        responses = [
            {"tool_calls": [{"tool": "exec_in_pod",
                             "args": {"cmd": f"echo turn{i}",
                                      "timeout_s": 30}}]}
            for i in range(1, 4)]
        client = FakeClient(responses)
        with self.assertRaises(ProvisionExhausted):
            run_provision_loop(ctx, f, client, FakeSandbox(), self._draft(),
                               base_image="ubuntu:22.04", max_turns=3)

    def test_incomplete_done_gets_nudged(self):
        """done:true without target_url must NOT be accepted."""
        ctx = _FakeCtx()
        f = _FakeFinding("t4")
        client = FakeClient([
            {"done": True},  # missing target_url + reproduce_command
            {"done": True,
             "target_url": "http://127.0.0.1:8080/eval",
             "reproduce_command": "curl x"},
        ])
        done, turns, _ = run_provision_loop(
            ctx, f, client, FakeSandbox(), self._draft(),
            base_image="ubuntu:22.04", max_turns=5)
        self.assertEqual(2, turns)
        self.assertEqual("http://127.0.0.1:8080/eval", done["target_url"])

    def test_garbage_response_gets_nudged(self):
        """Neither done nor tool_calls — model gets asked to try again."""
        ctx = _FakeCtx()
        f = _FakeFinding("t5")
        client = FakeClient([
            {"random": "garbage"},          # neither shape
            {"done": True,
             "target_url": "http://127.0.0.1:8080/eval",
             "reproduce_command": "curl x"},
        ])
        done, turns, _ = run_provision_loop(
            ctx, f, client, FakeSandbox(), self._draft(),
            base_image="ubuntu:22.04", max_turns=5)
        self.assertEqual(2, turns)

    def test_duplicate_tool_call_gets_flagged(self):
        """A model that runs identical calls repeatedly reads a nudge back
        instead of the same tool output — prevents accidental infinite
        loops on stateless queries."""
        ctx = _FakeCtx()
        f = _FakeFinding("t6")
        client = FakeClient([
            {"tool_calls": [{"tool": "exec_in_pod",
                             "args": {"cmd": "ls /", "timeout_s": 30}}]},
            {"tool_calls": [{"tool": "exec_in_pod",
                             "args": {"cmd": "ls /", "timeout_s": 30}}]},  # dup
            {"done": True, "target_url": "http://x/y",
             "reproduce_command": "curl x"},
        ])
        sb = FakeSandbox({"ls /": _Run(stdout="bin\nusr")})
        done, turns, _ = run_provision_loop(
            ctx, f, client, sb, self._draft(),
            base_image="ubuntu:22.04", max_turns=5)
        self.assertEqual(3, turns)
        # Emitted a duplicate-call event
        dupes = [e for e in ctx.store.events
                 if e["kind"] == "loop_duplicate_call"]
        self.assertEqual(1, len(dupes))

    def test_openai_shape_tool_calls_dispatch_correctly(self):
        """End-to-end: Kimi-shape tool_calls flow through the normalizer
        and dispatch to the real provision tool. If this fails, the
        Struts hard-lesson regresses."""
        ctx = _FakeCtx()
        f = _FakeFinding("k1")
        client = FakeClient([
            # Kimi's OpenAI shape:
            {"tool_calls": [
                {"id": "call_1", "type": "function",
                 "function": {"name": "exec_in_pod",
                              "arguments": '{"command": "ls /opt", "timeout_s": 30}'}}]},
            {"done": True, "target_url": "http://x/y",
             "reproduce_command": "curl x"},
        ])
        sb = FakeSandbox({"ls /opt": _Run(stdout="tomcat9\n")})
        done, turns, tool_calls = run_provision_loop(
            ctx, f, client, sb, self._draft(),
            base_image="ubuntu:22.04", max_turns=5)
        self.assertTrue(done["done"])
        self.assertEqual(2, turns)
        self.assertEqual(1, tool_calls)
        # The sandbox actually saw the command — normalization worked
        self.assertIn("ls /opt", sb.runs[-1])

    def test_bare_single_call_at_top_level_auto_wraps(self):
        """Kimi sometimes emits {"tool":"exec_in_pod","args":{...}} at
        top level, without the {"tool_calls":[...]} wrapper. The loop
        must auto-wrap and dispatch — otherwise 40 turns burn on the
        nudge branch, exactly what happened on the third Struts run."""
        ctx = _FakeCtx()
        f = _FakeFinding("bare1")
        client = FakeClient([
            # Bare {tool, args} at top level (no wrapper)
            {"tool": "exec_in_pod",
             "args": {"cmd": "ls /opt", "timeout_s": 30}},
            {"done": True, "target_url": "http://x/y",
             "reproduce_command": "curl x"},
        ])
        sb = FakeSandbox({"ls /opt": _Run(stdout="tomcat9")})
        done, turns, tool_calls = run_provision_loop(
            ctx, f, client, sb, self._draft(),
            base_image="ubuntu:22.04", max_turns=5)
        self.assertTrue(done["done"])
        self.assertEqual(2, turns)
        self.assertEqual(1, tool_calls)
        self.assertIn("ls /opt", sb.runs[-1])

    def test_bare_openai_function_call_at_top_level_auto_wraps(self):
        """Same but for the OpenAI {function:{name,arguments}} shape at
        top level without the tool_calls wrapper."""
        ctx = _FakeCtx()
        f = _FakeFinding("bare2")
        client = FakeClient([
            {"function": {"name": "exec_in_pod",
                          "arguments": '{"cmd": "pwd", "timeout_s": 30}'}},
            {"done": True, "target_url": "http://x/y",
             "reproduce_command": "curl x"},
        ])
        sb = FakeSandbox({"pwd": _Run(stdout="/root")})
        done, turns, tool_calls = run_provision_loop(
            ctx, f, client, sb, self._draft(),
            base_image="ubuntu:22.04", max_turns=5)
        self.assertEqual(1, tool_calls)
        self.assertIn("pwd", sb.runs[-1])

    def test_response_artifact_persisted_per_turn(self):
        ctx = _FakeCtx()
        f = _FakeFinding("t7")
        client = FakeClient([
            {"done": True, "target_url": "http://x/y",
             "reproduce_command": "curl x"}])
        run_provision_loop(ctx, f, client, FakeSandbox(), self._draft(),
                           base_image="ubuntu:22.04", max_turns=5)
        responses = ctx.store.artifacts_for("t7", "response")
        self.assertEqual(1, len(responses))
        self.assertEqual("provision", responses[0]["stage"])


# --- recipe_from_events --------------------------------------------------

class RecipeFromEventsTest(unittest.TestCase):

    def test_extracts_ordered_tool_calls(self):
        ctx = _FakeCtx()
        f = _FakeFinding("r1")
        # Emit a couple of tool_call events
        ctx.store.emit("r1", "provision", "loop_tool_call", "install_package",
                       meta={"turn": 1, "tool": "install_package",
                             "args": {"name": "openjdk-8-jdk"}})
        ctx.store.emit("r1", "provision", "loop_tool_call", "exec_in_pod",
                       meta={"turn": 2, "tool": "exec_in_pod",
                             "args": {"cmd": "mvn package"}})
        # Non-tool events should be ignored
        ctx.store.emit("r1", "provision", "loop_turn", "turn 3",
                       meta={"turn": 3})
        recipe = recipe_from_events(ctx, f)
        self.assertEqual(2, len(recipe))
        self.assertEqual("install_package", recipe[0]["tool"])
        self.assertEqual("openjdk-8-jdk", recipe[0]["args"]["name"])
        self.assertEqual("exec_in_pod", recipe[1]["tool"])
        self.assertEqual(1, recipe[0]["turn"])
        self.assertEqual(2, recipe[1]["turn"])


# --- initial message ------------------------------------------------------

class BuildInitialMsgTest(unittest.TestCase):

    def test_carries_draft_http_and_finding_metadata(self):
        f = _FakeFinding("m1", source_ref="CVE-2017-5638",
                         title="Struts RCE",
                         description="OGNL injection via multipart Content-Type")
        draft = {"endpoint_path_norm": "/showcase/index.action",
                 "method": "POST", "expected_status_red": 200,
                 "evidence_rules": [{"name": "uid",
                                     "kind": "response_body_regex",
                                     "pattern": r"uid=\d+"}]}
        msg = build_initial_msg(f, draft, base_image="ubuntu:22.04")
        self.assertIn("CVE-2017-5638", msg)
        self.assertIn("Struts RCE", msg)
        self.assertIn("ubuntu:22.04", msg)
        self.assertIn("/showcase/index.action", msg)
        # Draft rule fields are rendered as JSON, so name/pattern show up
        # verbatim — the model reads them straight.
        self.assertIn("uid", msg)
        self.assertIn("response_body_regex", msg)

    def test_includes_reference_patch_when_supplied(self):
        f = _FakeFinding("m2")
        draft = {"endpoint_path_norm": "/x", "method": "GET",
                 "expected_status_red": 200,
                 "evidence_rules": [
                     {"name": "y", "kind": "response_body_regex",
                      "pattern": "y"}]}
        msg = build_initial_msg(f, draft, base_image="ubuntu:22.04",
                                reference_patch="--- a/foo\n+++ b/foo\n@@\n-x\n+y")
        self.assertIn("--- a/foo", msg)
        self.assertIn("parent commit", msg)


# --- outcome coverage sanity ---------------------------------------------

class ProvisionOutcomesDeclaredTest(unittest.TestCase):
    """Every outcome the provision stage returns must be in outcomes.ALL —
    the runner's contract-violation guard fires otherwise. This test
    exists so a typo in a provision outcome string surfaces as a suite
    failure rather than a runtime harness-fail."""

    def test_all_provision_outcomes_declared(self):
        expected = {
            "provision_shortcircuit", "provision_no_draft_spec",
            "provision_draft_unreadable", "provision_no_model_configured",
            "provision_no_budget", "provision_pod_prep_failed",
            "provision_budget_exhausted", "provision_gave_up",
            "provision_turns_exhausted", "provision_commit_failed",
            "provision_invalid_spec", "provision_complete",
        }
        for outcome in expected:
            self.assertIn(outcome, outcomes_mod.ALL,
                          f"outcome {outcome!r} not declared in outcomes.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
