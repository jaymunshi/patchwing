"""Tests for symptom-based localization.

The claim: PatchWing can find the vulnerable file from a bug report alone, with no
upstream fix to read the answer off. These tests cover the deterministic parts —
trace parsing, project-file matching, revision narrowing, and the precedence rule
that stops advisory prose overriding a frame that was demonstrably executing.

The model-ranking step is exercised with a stub. This module's accuracy is
UNMEASURED — see the note in symptom.py. A prior 68.4% figure belongs to a
superseded, advisory-only implementation and must not be attributed here.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import symptom  # noqa: E402

PY_TRACE = '''Traceback (most recent call last):
  File "/app/run.py", line 3, in <module>
    store.read_note("../../etc/passwd")
  File "/usr/lib/python3.12/posixpath.py", line 90, in join
    a = os.fspath(a)
  File "/app/notes/store.py", line 12, in read_note
    return open(target).read()
PermissionError
'''

ASAN_TRACE = '''==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x4f1a2b in parse_header /src/proj/parser.c:88:14
    #1 0x4f2c11 in handle /src/proj/server.c:210:5
    #2 0x7f0000 in __libc_start_main /usr/lib/libc.so:120
'''


class StubClient:
    """Returns a fixed ranking; records the prompt so we can assert on evidence."""

    def __init__(self, ranked):
        self.ranked = ranked
        self.prompt = ""

    def chat(self, messages, **kw):
        self.prompt = messages[-1]["content"]
        import json as _j
        return _j.dumps({"ranked": self.ranked, "why": "stub"})


class TraceParsingTest(unittest.TestCase):
    def test_parses_python_frames(self):
        frames = symptom.parse_trace(PY_TRACE)
        paths = [p for p, _ in frames]
        self.assertIn("/app/notes/store.py", paths)
        self.assertIn("/app/run.py", paths)

    def test_drops_stdlib_frames(self):
        paths = [p for p, _ in symptom.parse_trace(PY_TRACE)]
        self.assertNotIn("/usr/lib/python3.12/posixpath.py", paths,
                         "stdlib frames are not patchable and must be filtered")

    def test_parses_asan_frames(self):
        frames = symptom.parse_trace(ASAN_TRACE)
        paths = [p for p, _ in frames]
        self.assertIn("/src/proj/parser.c", paths)
        self.assertIn("/src/proj/server.c", paths)
        self.assertNotIn("/usr/lib/libc.so", paths)

    def test_line_numbers_captured(self):
        frames = dict(symptom.parse_trace(PY_TRACE))
        self.assertEqual(frames["/app/notes/store.py"], 12)

    def test_empty_trace_is_safe(self):
        self.assertEqual(symptom.parse_trace(""), [])
        self.assertEqual(symptom.parse_trace(None), [])


class ProjectTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pw-sym-")
        for rel in ("notes/store.py", "run.py", "notes/util.py",
                    "tests/test_store.py"):
            p = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write("x = 1\n")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_candidates_exclude_tests(self):
        c = symptom.enumerate_candidates(self.root)
        self.assertIn("notes/store.py", c)
        self.assertNotIn("tests/test_store.py", c)

    def test_trace_files_match_by_suffix(self):
        """Traces carry absolute runtime paths; the checkout is elsewhere."""
        hits = symptom.trace_files(PY_TRACE, self.root)
        self.assertIn("notes/store.py", hits)

    def test_trace_frame_outranks_model_prose(self):
        client = StubClient(["notes/util.py", "run.py", "notes/store.py"])
        res = symptom.localize(client, self.root,
                               advisory="something about util", trace=PY_TRACE)
        self.assertEqual(res["files"][0], "notes/store.py",
                         "a file the trace proves was executing must outrank prose")

    def test_advisory_only_falls_back_to_model_order(self):
        client = StubClient(["notes/util.py", "run.py"])
        res = symptom.localize(client, self.root, advisory="util is broken")
        self.assertEqual(res["files"][0], "notes/util.py")
        self.assertEqual(res["evidence"]["stack_trace_frames"], 0)

    def test_evidence_is_recorded(self):
        client = StubClient(["notes/store.py"])
        res = symptom.localize(client, self.root, advisory="a", trace=PY_TRACE,
                               poc="GET /../../etc/passwd")
        ev = res["evidence"]
        self.assertTrue(ev["has_poc"])
        self.assertGreater(ev["stack_trace_frames"], 0)
        self.assertIn("notes/store.py", ev["stack_trace_files"])

    def test_model_failure_falls_back_to_trace(self):
        class Boom:
            def chat(self, *a, **k):
                raise RuntimeError("endpoint down")
        res = symptom.localize(Boom(), self.root, advisory="a", trace=PY_TRACE)
        self.assertNotIn("error", res)
        self.assertEqual(res["files"][0], "notes/store.py")

    def test_model_failure_with_no_trace_is_an_error(self):
        class Boom:
            def chat(self, *a, **k):
                raise RuntimeError("endpoint down")
        res = symptom.localize(Boom(), self.root, advisory="a")
        self.assertIn("error", res)

    def test_hallucinated_paths_are_dropped(self):
        client = StubClient(["totally/made/up.py", "notes/store.py"])
        res = symptom.localize(client, self.root, advisory="a")
        self.assertNotIn("totally/made/up.py", res["ranked"])
        self.assertEqual(res["files"][0], "notes/store.py")

    def test_evidence_appears_above_prose_in_prompt(self):
        client = StubClient(["notes/store.py"])
        symptom.localize(client, self.root, advisory="ADVISORY_TEXT", trace=PY_TRACE)
        self.assertLess(client.prompt.index("Stack trace"),
                        client.prompt.index("## Advisory"),
                        "direct evidence must be presented before the prose")


class RevisionTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pw-rev-")
        self.git = shutil.which("git")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _run(self, *args):
        subprocess.run(["git", "-C", self.root] + list(args),
                       capture_output=True, check=False)

    def test_narrow_by_revision(self):
        if not self.git:
            self.skipTest("git not available")
        self._run("init", "-q")
        self._run("config", "user.email", "t@t")
        self._run("config", "user.name", "t")
        open(os.path.join(self.root, "a.py"), "w").write("1\n")
        open(os.path.join(self.root, "b.py"), "w").write("1\n")
        self._run("add", "-A")
        self._run("commit", "-qm", "base")
        open(os.path.join(self.root, "b.py"), "w").write("2\n")
        self._run("add", "-A")
        self._run("commit", "-qm", "bug")
        files = symptom.narrow_by_revision(self.root, "HEAD~1", "HEAD")
        self.assertEqual(files, ["b.py"])

    def test_missing_range_returns_empty_not_error(self):
        self.assertEqual(symptom.narrow_by_revision(self.root, "", ""), [])

    def test_non_repo_returns_empty(self):
        self.assertEqual(symptom.narrow_by_revision(self.root, "a", "b"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
