"""Tests for the reproducer-only closed-loop investigation.

Properties pinned:
  - `edits` returned by the model triggers apply+build+reproduce inside the
    loop; a still-red reproducer feeds the new trace back and the loop keeps
    going in the SAME conversation.
  - A chain-proved patch (post-patch green, post-rollback red) exits the loop
    with StageResult.ok — the outer patch stage writes the patch artifact
    normally.
  - Explicit `give_up` from the model produces terminal patch_investigation_gave_up.
  - Duplicate tool calls (same tool, same args after normalization) do NOT
    re-execute; they return a nudge to the model instead.
  - Hard turn cap trips patch_investigation_exhausted, not
    infrastructure_failure.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import stages                       # noqa: E402
from patchwing.models import Usage                 # noqa: E402
from patchwing.store import Store                  # noqa: E402


SOURCE_BUF_C = """int xmlBufferCreate(void) {
    xmlBufPtr ret = malloc(sizeof(*ret));
    ret->content = malloc(32);
    ret->content[0] = 0;
    return ret;
}
"""

SOURCE_SAX2_C = """void xmlSAX2CDataBlock(void *ctx, const xmlChar *value, int len) {
    xmlNodePtr ret;
    ret = xmlNewCDataBlock(ctxt->myDoc, value, len);
    xmlAddChild(ctxt->node, ret);
}
"""


class FakeCfg:
    model = "moonshotai/Kimi-K2.7-Code"
    endpoint = "http://x/v1"
    temperature = 0.2
    max_tokens = 4096
    role = "patch"
    family = "kimi"
    extra: dict = {}


class SequenceClient:
    def __init__(self, responses):
        self.cfg = FakeCfg()
        self._responses = list(responses)
        self.calls: list[list[dict]] = []
        self.usage = Usage()
        self.last_raw_response = "{}"

    def chat_json(self, messages, required=()):
        self.calls.append(list(messages))
        if not self._responses:
            raise RuntimeError(
                f"SequenceClient exhausted after {len(self.calls)} calls")
        return self._responses.pop(0)


class FakeRunResult:
    def __init__(self, stdout="", stderr="", rc=0, timed_out=False):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = rc
        self.timed_out = timed_out


class FakeSandbox:
    """Minimal pod emulator.

    - `read()` returns the current in-memory file content.
    - `write()` updates in-memory content.
    - `run()` emulates the shell commands the investigation loop and its
      inner-loop verify actually issue (test-f marker, grep, ls, build,
      reproduce). Configurable behaviour so a test can say "reproducer goes
      green after buf.c is patched, red otherwise."
    """

    def __init__(self, files, *, build_returncode=0, repro_when_patched="green",
                 repro_when_pristine="red", patched_marker_file="buf.c",
                 patched_marker_contains="memset"):
        self._files = dict(files)
        self.cid = "fake-cid"
        self.run_log: list[str] = []
        self.build_returncode = build_returncode
        self.repro_when_patched = repro_when_patched
        self.repro_when_pristine = repro_when_pristine
        self._marker_file = patched_marker_file
        self._marker_contains = patched_marker_contains
        self._setup_marker_present = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def prepare(self):
        pass

    def read(self, path):
        if path in self._files:
            return self._files[path]
        for k, v in self._files.items():
            if k.endswith("/" + path.lstrip("/")) or path.endswith("/" + k):
                return v
        from patchwing.sandbox import SandboxError
        raise SandboxError(f"file not found: {path}")

    def write(self, path, content):
        # normalize: strip container root prefix if present
        norm = path
        for k in list(self._files):
            if norm.endswith("/" + k) or norm == k:
                norm = k
                break
        self._files[norm] = content

    def _repro_output(self):
        """Green if the marker file contains the marker string; red otherwise."""
        current = self._files.get(self._marker_file, "")
        if self._marker_contains in current:
            state = self.repro_when_patched
        else:
            state = self.repro_when_pristine
        if state == "green":
            return FakeRunResult(stdout="ok", rc=0)
        # red — sanitizer marker + a stable dedup token
        red_output = (
            "==1==ERROR: MemorySanitizer: use-of-uninitialized-value\n"
            "    #0 0x1 in xmlNextChar\n"
            "DEDUP_TOKEN: xmlNextChar--xmlParseCharRef--xmlParseAttValueComplex\n"
        )
        return FakeRunResult(stdout=red_output, rc=77)

    def run(self, cmd, cwd=None, timeout_s=None):
        self.run_log.append(cmd)
        if cmd.startswith("test -f"):
            return FakeRunResult(rc=0 if self._setup_marker_present else 1)
        if cmd.startswith("touch "):
            self._setup_marker_present = True
            return FakeRunResult(rc=0)
        if cmd.startswith("ls "):
            return FakeRunResult(stdout="\n".join(self._files), rc=0)
        if "grep" in cmd:
            import shlex
            try:
                parts = shlex.split(cmd)
            except ValueError:
                return FakeRunResult(rc=2, stderr="bad command")
            if "--" not in parts:
                return FakeRunResult(rc=2, stderr="unexpected grep form")
            i = parts.index("--")
            if i + 1 >= len(parts):
                return FakeRunResult(rc=2, stderr="missing pattern")
            pattern = parts[i + 1]
            hits = []
            for path, content in self._files.items():
                for lineno, line in enumerate(content.splitlines(), 1):
                    if pattern in line:
                        hits.append(f"{path}:{lineno}:{line}")
            return FakeRunResult(stdout="\n".join(hits),
                                 rc=0 if hits else 1)
        # build command: matches make / clang / arvo compile
        if any(tok in cmd for tok in ("make ", "arvo compile", "clang")):
            return FakeRunResult(rc=self.build_returncode)
        # reproducer command: matches arvo run / /out/... executables
        if "arvo run" in cmd or "/out/" in cmd or cmd.strip().startswith("./"):
            return self._repro_output()
        return FakeRunResult(rc=0)


class Ctx:
    def __init__(self, store):
        self.store = store
        self.workdir = tempfile.mkdtemp()
        self.config = None


class InvestigationBaseTest(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db_path)
        self.f = self.store.add_finding(
            source="manual", repo_url="http://example.invalid",
            title="uninit read in xmlNextChar via encoding switch",
            description="MSan trace shows xmlNextChar reading uninit bytes.",
            stage="patch")

        # Spec with build+reproduce commands so the closed loop can actually
        # run against the fake sandbox.
        spec = {
            "target": {"root": "/src", "mode": "in-image"},
            "files": [{"path": "buf.c"}],
            "language": "c",
            "commands": {
                "build": "arvo compile",
                "incremental_build": "make -j$(nproc)",
                "reproduce": "arvo run",
            },
            "fix_writer": {"investigation_mode": True,
                           "investigation_max_turns": 4},
        }
        self.store.add_artifact(self.f.id, "spec", "ingest",
                                json.dumps(spec), {}, "", "")
        self.store.add_artifact(self.f.id, "localization", "localize",
                                "buf.c", {"files": ["buf.c"]}, "", "")
        # Reproducer artifact must include the pristine DEDUP_TOKEN so the
        # inner-loop classifier can compare against it.
        pristine = (
            "==1==ERROR: MemorySanitizer: use-of-uninitialized-value\n"
            "    #0 0x1 in xmlNextChar\n"
            "DEDUP_TOKEN: xmlNextChar--xmlParseCharRef--xmlParseAttValueComplex\n"
        )
        self.store.add_artifact(self.f.id, "reproducer", "reproduce",
                                pristine, {}, "", "")
        lock = {"algorithm": "sha256", "n_files": 1, "n_reproducer": 1,
                "files": {"/tmp/poc": {"reason": "reproducer",
                                       "sha256": "0" * 64, "bytes": 0}},
                "pristine_dedup_token":
                    "xmlNextChar--xmlParseCharRef--xmlParseAttValueComplex",
                "pristine_marker": "MemorySanitizer",
                "pristine_returncode": 77}
        self.store.add_artifact(self.f.id, "reproducer_lock", "reproduce",
                                json.dumps(lock), {}, "", "")

        self.sandbox_files = {"buf.c": SOURCE_BUF_C, "SAX2.c": SOURCE_SAX2_C}
        self._orig_sandbox = stages._sandbox
        self._orig_client = stages._client
        self._sb = FakeSandbox(self.sandbox_files)
        stages._sandbox = lambda ctx, spec=None, finding=None, persist=False: self._sb

    def tearDown(self):
        stages._sandbox = self._orig_sandbox
        stages._client = self._orig_client
        self.store.close()
        os.unlink(self.db_path)

    def _install_client(self, responses):
        self.client = SequenceClient(responses)
        stages._client = lambda ctx, role, finding=None, stage_name="": self.client

    def _events(self, kind: str | None = None):
        rows = self.store.conn.execute(
            "SELECT kind, message FROM events WHERE finding_id = ? "
            "ORDER BY id ASC", (self.f.id,)).fetchall()
        if kind is None:
            return rows
        return [r for r in rows if r[0] == kind]


class InvestigationClosedLoopConvergesTest(InvestigationBaseTest):

    def test_investigate_then_patch_chain_proved_exits_ok(self):
        """T1: model requests one grep. T2: model returns a patch that puts
        `memset(...)` into buf.c. Fake sandbox reports green after patch,
        red after revert (chain proved). Loop exits, stage returns ok."""
        turn1 = {
            "reasoning": "look for the allocation site",
            "tool_calls": [
                {"tool": "grep",
                 "args": {"pattern": "content[0]", "path_glob": "*.c"}},
            ],
        }
        turn2 = {
            "analysis": "zero the entire allocation to close the uninit read",
            "edits": ("<<<<<<< SEARCH\n"
                      "    ret->content[0] = 0;\n"
                      "=======\n"
                      "    memset(ret->content, 0, 32);\n"
                      ">>>>>>> REPLACE\n"),
            "confidence": "high",
        }
        # Extra give-ups as safety net if the loop misfires; the test asserts
        # chain-proved exit before consuming them.
        give_up = {"give_up": "safety-net; should not be reached"}
        self._install_client([turn1, turn2, give_up, give_up])
        result = stages.patch(self.f, Ctx(self.store))

        # Chain proved in inner loop → outer patch stage returns ok
        self.assertEqual(result.status, "ok",
                         f"expected ok, got {result.status}: {result.message}")
        self.assertEqual(result.meta.get("outcome"), "patch_written")

        # Timeline should record the closed-loop events
        kinds = [r[0] for r in self._events()]
        self.assertIn("investigation_patch_returned", kinds)
        self.assertIn("loop_build_start", kinds)
        self.assertIn("loop_reproducer_done", kinds)
        self.assertIn("loop_four_state", kinds)
        self.assertIn("loop_rollback_reproducer_done", kinds)
        self.assertIn("investigation_chain_proved", kinds)


class PodStateHandoffTest(InvestigationBaseTest):
    """Pins the handoff: when the inner loop chain-proves and returns to the
    outer patch stage, the pod's file must be at PRISTINE bytes, not the
    patched bytes. Otherwise the outer verify stage's `pre_source = sb.read(rel)`
    snapshot captures already-patched bytes and the whole hash triple
    (before/after/revert) collapses to a single value — the "before !=
    after, revert == before" assertion becomes trivially satisfied while
    proving nothing about the fix."""

    def test_pod_left_pristine_on_chain_proved(self):
        turn1 = {"reasoning": "look for the allocation site",
                 "tool_calls": [{"tool": "grep",
                                 "args": {"pattern": "content[0]",
                                          "path_glob": "*.c"}}]}
        turn2 = {"analysis": "zero the buffer at allocation",
                 "edits": ("<<<<<<< SEARCH\n"
                           "    ret->content[0] = 0;\n"
                           "=======\n"
                           "    memset(ret->content, 0, 32);\n"
                           ">>>>>>> REPLACE\n"),
                 "confidence": "high"}
        give_up = {"give_up": "safety-net"}
        self._install_client([turn1, turn2, give_up, give_up])
        result = stages.patch(self.f, Ctx(self.store))
        self.assertEqual(result.status, "ok",
                         f"chain-proved run should return ok, got {result.status}")

        # The critical assertion: pod's buf.c must match the PRISTINE bytes
        # the loop started from, NOT the patched bytes. This is what makes
        # the outer verify stage's rollback assertion meaningful.
        pod_bytes = self._sb.read("buf.c")
        self.assertEqual(pod_bytes, SOURCE_BUF_C,
                         "on chain-proved exit, the pod must hold pristine "
                         "bytes so the outer verify's before-snapshot is "
                         "pristine — otherwise the hash triple collapses to "
                         "one value and the rollback assertion is meaningless")
        self.assertNotIn("memset", pod_bytes,
                         "buf.c on pod must not contain the patch's memset "
                         "call after chain-proved return")


class InvestigationGiveUpTest(InvestigationBaseTest):

    def test_give_up_is_terminal(self):
        response = {"give_up":
                    "the read site depends on encoding-switch state I cannot "
                    "reason about without runtime instrumentation the tools do "
                    "not provide"}
        self._install_client([response])
        result = stages.patch(self.f, Ctx(self.store))

        self.assertEqual(result.status, "fail",
                         f"expected fail, got {result.status}: {result.message}")
        self.assertEqual(result.meta.get("outcome"),
                         "patch_investigation_gave_up")
        self.assertIn("encoding-switch state",
                      result.meta.get("give_up_reason", ""))
        # Exactly 1 model call — no retry after give_up
        self.assertEqual(len(self.client.calls), 1)


class InvestigationDuplicateCallNudgeTest(InvestigationBaseTest):

    def test_second_identical_grep_returns_nudge_not_result(self):
        """T1 and T2 issue the exact same grep. T2's tool result must be the
        nudge, NOT a re-executed grep. Anti-circling in action."""
        t1 = {"reasoning": "first check",
              "tool_calls": [{"tool": "grep",
                              "args": {"pattern": "content[0]",
                                       "path_glob": "*.c"}}]}
        t2 = {"reasoning": "check again",
              "tool_calls": [{"tool": "grep",
                              "args": {"pattern": "content[0]",
                                       "path_glob": "*.c"}}]}
        # After we've observed the nudge, model gives up
        t3 = {"give_up": "no new leads"}
        self._install_client([t1, t2, t3])
        result = stages.patch(self.f, Ctx(self.store))

        # It should have completed with the give-up terminal outcome
        self.assertEqual(result.meta.get("outcome"),
                         "patch_investigation_gave_up")

        # Timeline should carry a duplicate-call event
        dup_events = self._events("investigation_duplicate_call")
        self.assertGreaterEqual(len(dup_events), 1,
                                "expected at least one duplicate_call event")

        # Turn 3's convo must contain the nudge text (fed back as the T2 tool
        # results after the duplicate was detected)
        third_convo = self.client.calls[2]
        # Look at the most recent user message with tool results — it should
        # carry the nudge phrase.
        last_user = next((m["content"] for m in reversed(third_convo)
                          if m["role"] == "user"), "")
        self.assertIn("already ran this exact call", last_user)
        self.assertIn("try a genuinely different investigation angle",
                      last_user)


class InvestigationBudgetExhaustsTest(InvestigationBaseTest):

    def test_never_returning_patch_hits_turn_cap_terminal(self):
        """Model returns only tool_calls, never a patch or give_up. The
        4-turn cap trips patch_investigation_exhausted, not infra failure."""
        stall = {"reasoning": "still looking",
                 "tool_calls": [{"tool": "list_dir",
                                 "args": {"path": "/src"}}]}
        self._install_client([stall] * 4)
        result = stages.patch(self.f, Ctx(self.store))

        self.assertEqual(result.status, "fail",
                         f"expected fail, got {result.status}: {result.message}")
        self.assertEqual(result.meta.get("outcome"),
                         "patch_investigation_exhausted")
        self.assertFalse(result.meta.get("patch_evaluated", True))
        self.assertLessEqual(len(self.client.calls), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
