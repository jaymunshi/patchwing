"""Tests for schema-violation handling in the patch stage.

The 1076 sibling-scan rerun hit a `TypeError` because Kimi returned
`"edits": []` — a JSON array — instead of the schema's required string of
concatenated SEARCH/REPLACE blocks. The runner classified the crash as
`infrastructure_failure`, which is exactly what the outcome-uniqueness guard
was built to prevent: a model-output failure wearing an infrastructure mask.

Property pinned by these tests: when the model returns `edits` as anything
other than a string, the patch stage terminates with
`patch_edits_wrong_type`, `patch_evaluated=False`, exactly ONE model call
(no auto-retry), and a timeline event that names the actual type. The fix
for this class of failure lives in the prompt, not in a retry loop —
retrying a model that returned `[]` is very likely to yield another `[]`.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import stages                              # noqa: E402
from patchwing.models import Usage                        # noqa: E402
from patchwing.store import Store                         # noqa: E402


SOURCE = """int xmlBufferCreate(void) {
    xmlBufPtr ret = malloc(sizeof(*ret));
    ret->content = malloc(32);
    ret->content[0] = 0;
    return ret;
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
        self.calls.append(messages)
        return self._responses.pop(0)


class FakeSandbox:
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
    def __init__(self, store):
        self.store = store
        self.workdir = tempfile.mkdtemp()
        self.config = None


class EditsWrongTypeTest(unittest.TestCase):

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db_path)
        self.f = self.store.add_finding(
            source="manual", repo_url="http://example.invalid",
            title="1076 rerun regression fixture",
            description="pin the schema-violation path",
            stage="patch")

        spec = {"target": {"root": "/src", "mode": "in-image"},
                "files": [{"path": "buf.c"}]}
        self.store.add_artifact(self.f.id, "spec", "ingest",
                                json.dumps(spec), {}, "", "")
        self.store.add_artifact(self.f.id, "localization", "localize",
                                "buf.c", {"files": ["buf.c"]}, "", "")
        self.store.add_artifact(self.f.id, "reproducer", "reproduce",
                                "", {}, "", "")
        lock_manifest = {
            "algorithm": "sha256",
            "n_files": 1, "n_reproducer": 1,
            "files": {"/tmp/poc": {"reason": "reproducer",
                                   "sha256": "0" * 64, "bytes": 0}},
        }
        self.store.add_artifact(self.f.id, "reproducer_lock", "reproduce",
                                json.dumps(lock_manifest), {}, "", "")

        self._orig_sandbox = stages._sandbox
        self._orig_client = stages._client
        stages._sandbox = lambda ctx, spec=None, finding=None, persist=False: \
            FakeSandbox({"buf.c": SOURCE})

    def tearDown(self):
        stages._sandbox = self._orig_sandbox
        stages._client = self._orig_client
        self.store.close()
        os.unlink(self.db_path)

    def _install_client(self, responses):
        self.client = SequenceClient(responses)
        stages._client = lambda ctx, role, finding=None, stage_name="": self.client

    def test_edits_list_yields_terminal_wrong_type_outcome(self):
        """Kimi's actual 1076 response was `{"edits": []}`. That failure now
        terminates cleanly with a named outcome instead of a TypeError crash
        classified as infrastructure — which was the whole point of the
        outcome closed-set."""
        self._install_client([
            {"analysis": "the model reasoned correctly but returned a list",
             "edits": [],
             "confidence": "high"},
        ])
        result = stages.patch(self.f, Ctx(self.store))

        self.assertEqual(result.status, "fail",
                         f"expected fail, got {result.status}: {result.message}")
        self.assertEqual(result.meta.get("outcome"), "patch_edits_wrong_type")
        self.assertEqual(result.meta.get("actual_type"), "list")
        self.assertFalse(result.meta.get("patch_evaluated", True),
                         "an unevaluated patch must never wear a verdict")
        self.assertEqual(len(self.client.calls), 1,
                         "no auto-retry — a model that returned list once is "
                         "likely to return list again; fix belongs in the prompt")
        self.assertIn("list", result.message)

        # Timeline event carries the actual type so the paper can characterize
        # the failure without re-reading the response artifact.
        kinds = [r[0] for r in self.store.conn.execute(
            "SELECT kind FROM events WHERE finding_id = ? ORDER BY id ASC",
            (self.f.id,)).fetchall()]
        self.assertIn("patch_edits_wrong_type", kinds)

    def test_edits_dict_yields_terminal_wrong_type_outcome(self):
        """The same guard for `edits` returned as an object. Same terminal
        outcome, different actual_type."""
        self._install_client([
            {"analysis": "the model shaped its output as an object",
             "edits": {"file": "buf.c", "block": "..."},
             "confidence": "high"},
        ])
        result = stages.patch(self.f, Ctx(self.store))

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.meta.get("outcome"), "patch_edits_wrong_type")
        self.assertEqual(result.meta.get("actual_type"), "dict")


if __name__ == "__main__":
    unittest.main(verbosity=2)
