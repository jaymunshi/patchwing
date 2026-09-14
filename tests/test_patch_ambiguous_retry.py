"""Tests for the single-retry-on-ambiguous-SEARCH loop in stages.patch.

The principle being pinned: when a validator rejects a model output, retry the
model ONCE with the exact validator message, then fail loud. No autofix, no
±N-line expansion, no global prompt rule for a failure that only happens
sometimes. The model stays accountable; PatchWing never reshapes model output.

Two properties matter:
  1. First-try ambiguous, retry unique → success, outcome=patch_written, one
     extra model call.
  2. First-try ambiguous, retry ambiguous → terminal fail,
     outcome=patch_ambiguous_after_retry, no third call. Real information about
     the model, not a case for further retries.

The tests exercise the whole patch() stage via a fake client (SequenceClient)
and a fake sandbox — the same shape test_seats.py already uses for reviewer
tests. Anything higher up the stack (localization artifact, spec, store) is
real, so the assertions cover the wiring that would break silently if the
retry loop were bypassed.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import edit, stages                        # noqa: E402
from patchwing.models import Usage                        # noqa: E402
from patchwing.store import Store                         # noqa: E402


SOURCE_WITH_DUPLICATED_LINE = """int xmlBufferCreate(void) {
    xmlBufPtr ret = malloc(sizeof(*ret));
    ret->size = 32;
    ret->content = malloc(ret->size);
    ret->content[0] = 0;
    return ret;
}

int xmlBufferCreateSize(size_t size) {
    xmlBufPtr ret = malloc(sizeof(*ret));
    ret->size = size ? size : 32;
    ret->content = malloc(ret->size);
    ret->content[0] = 0;
    return ret;
}
"""

# The ambiguous SEARCH — matches twice in SOURCE_WITH_DUPLICATED_LINE. This is
# exactly what Kimi returned on the 1076 CData leak: the right insight (memset
# at allocation) but one-line SEARCH.
AMBIGUOUS_EDIT = """<<<<<<< SEARCH
    ret->content[0] = 0;
=======
    memset(ret->content, 0, ret->size);
>>>>>>> REPLACE
"""

# A unique SEARCH — three lines of context around the target, which happens to
# match only the first constructor. This is what a well-behaved retry would
# return.
DISAMBIGUATED_EDIT = """<<<<<<< SEARCH
int xmlBufferCreate(void) {
    xmlBufPtr ret = malloc(sizeof(*ret));
    ret->size = 32;
    ret->content = malloc(ret->size);
    ret->content[0] = 0;
=======
int xmlBufferCreate(void) {
    xmlBufPtr ret = malloc(sizeof(*ret));
    ret->size = 32;
    ret->content = malloc(ret->size);
    memset(ret->content, 0, ret->size);
>>>>>>> REPLACE
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
    """Returns preset chat_json responses in order. Records call count so a
    test can prove a second (retry) call did or did not happen."""

    def __init__(self, responses):
        self.cfg = FakeCfg()
        self._responses = list(responses)
        self.calls: list[list[dict]] = []
        self.usage = Usage()
        self.last_raw_response = "{}"

    def chat_json(self, messages, required=()):
        self.calls.append(messages)
        if not self._responses:
            raise RuntimeError("SequenceClient exhausted — the stage made "
                               f"{len(self.calls)} calls, one more than the "
                               "test set up. That extra call is a bug.")
        resp = self._responses.pop(0)
        for k in required:
            if k not in resp:
                raise AssertionError(
                    f"test bug: fake response missing required key {k!r}")
        return resp


class FakeSandbox:
    """Bare-minimum context-manager that gives patch() a source string. The
    real sandbox reads from a container; the retry loop only cares that some
    bytes come back."""

    def __init__(self, files):
        self._files = dict(files)
        self.cid = "fake-cid"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def prepare(self):
        pass

    def read(self, path):
        if path not in self._files:
            raise FileNotFoundError(path)
        return self._files[path]


class Ctx:
    """Minimal context with a real store (in-memory) and no ambient config."""

    def __init__(self, store):
        self.store = store
        self.workdir = tempfile.mkdtemp()
        self.config = None


class _StageMockingCase(unittest.TestCase):
    """Base — restores every stages.* function we monkey-patch."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db_path)
        self.f = self.store.add_finding(
            source="manual", repo_url="http://example.invalid",
            title="use of uninitialized value in xmlNextChar",
            description="test fixture for ambiguity retry loop",
            stage="patch")

        # Seed the artifacts patch() reads before the model call. mode=in-image
        # so the primary source is read via _sandbox (which the test mocks),
        # not from a real host directory.
        spec = {"target": {"root": "/src", "mode": "in-image"},
                "files": [{"path": "buf.c"}]}
        self.store.add_artifact(self.f.id, "spec", "ingest",
                                json.dumps(spec), {}, "", "")
        self.store.add_artifact(self.f.id, "localization", "localize",
                                "buf.c", {"files": ["buf.c"]}, "", "")
        # Empty reproducer so _localize_from_trace returns nothing → spec-file
        # fallback kicks in.
        self.store.add_artifact(self.f.id, "reproducer", "reproduce",
                                "", {}, "", "")
        # A reproducer_lock manifest that names some OTHER file — buf.c must
        # not appear in it, or wall.assert_patchable refuses the patch target.
        lock_manifest = {
            "algorithm": "sha256",
            "n_files": 1, "n_reproducer": 1,
            "files": {"/tmp/poc": {"reason": "reproducer",
                                   "sha256": "0" * 64, "bytes": 0}},
        }
        self.store.add_artifact(self.f.id, "reproducer_lock", "reproduce",
                                json.dumps(lock_manifest), {}, "", "")

        # Monkey-patch the seams. Restored in tearDown so tests do not leak.
        self._orig_sandbox = stages._sandbox
        self._orig_client = stages._client
        stages._sandbox = lambda ctx, spec=None, finding=None, persist=False: \
            FakeSandbox({"buf.c": SOURCE_WITH_DUPLICATED_LINE})

    def tearDown(self):
        stages._sandbox = self._orig_sandbox
        stages._client = self._orig_client
        self.store.close()
        os.unlink(self.db_path)

    def _install_client(self, responses):
        self.client = SequenceClient(responses)
        stages._client = lambda ctx, role, finding=None, stage_name="": self.client

    def _events(self, kind: str | None = None) -> list:
        rows = self.store.conn.execute(
            "SELECT kind, message FROM events WHERE finding_id = ? "
            "ORDER BY id ASC", (self.f.id,)).fetchall()
        if kind is None:
            return rows
        return [r for r in rows if r[0] == kind]


class AmbiguityRetrySucceedsTest(_StageMockingCase):

    def test_first_try_ambiguous_second_try_unique_wins(self):
        """The model's first edit hits a duplicated line. PatchWing sends back
        the exact validator message. The model returns an expanded SEARCH the
        second time and the patch applies."""
        self._install_client([
            {"analysis": "memset at allocation",
             "edits": AMBIGUOUS_EDIT,
             "confidence": "high"},
            {"analysis": "expanded search block for uniqueness",
             "edits": DISAMBIGUATED_EDIT,
             "confidence": "high"},
        ])
        result = stages.patch(self.f, Ctx(self.store))

        self.assertEqual(result.status, "ok",
                         f"expected ok, got {result.status}: {result.message}")
        self.assertEqual(result.meta.get("outcome"), "patch_written")
        self.assertEqual(len(self.client.calls), 2,
                         "the retry should have caused exactly one extra call")

        # The second call's convo must carry the previous response and the
        # disambiguation note — otherwise the model is being asked cold and the
        # accountability chain is broken.
        retry_convo = self.client.calls[1]
        roles = [m["role"] for m in retry_convo]
        self.assertEqual(roles, ["system", "user", "assistant", "user"],
                         "retry convo must be system + user + assistant "
                         "(previous JSON) + user (validator note)")
        note = retry_convo[-1]["content"]
        self.assertIn("SEARCH block 1 of 1 matched 2 times in buf.c", note)
        self.assertIn("expanded until unique", note)

        # Timeline substeps must record what happened; a silent recovery is
        # exactly the failure mode the paste warned against.
        kinds = [r[0] for r in self._events()]
        self.assertIn("patch_ambiguous", kinds)
        self.assertIn("patch_retry_ambiguous", kinds)


class AmbiguityRetryFailsTerminalTest(_StageMockingCase):

    def test_retry_also_ambiguous_is_terminal(self):
        """The model returns ambiguous SEARCH twice in a row. Terminal — do not
        keep spending attempts on a model that cannot follow a failure message."""
        self._install_client([
            {"analysis": "memset at allocation",
             "edits": AMBIGUOUS_EDIT,
             "confidence": "high"},
            {"analysis": "memset at allocation (still ambiguous)",
             "edits": AMBIGUOUS_EDIT,
             "confidence": "high"},
        ])
        result = stages.patch(self.f, Ctx(self.store))

        self.assertEqual(result.status, "fail",
                         f"expected fail, got {result.status}: {result.message}")
        self.assertEqual(result.meta.get("outcome"),
                         "patch_ambiguous_after_retry")
        self.assertFalse(result.meta.get("patch_evaluated", True),
                         "an unevaluated patch must never wear a verdict")
        self.assertEqual(len(self.client.calls), 2,
                         "one bound — a third call means the loop has grown "
                         "an autofix instinct")
        self.assertIn("real information about the model",
                      result.message.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
