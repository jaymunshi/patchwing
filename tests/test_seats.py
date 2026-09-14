"""Tests for seat separation.

The addendum's claim is that trust lives in the reproducer and the container, not in
model identity. These tests pin the two properties that make that true in code:
the reviewer cannot change a verdict, and its config travels with its opinion.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import stages  # noqa: E402
from patchwing.store import Store  # noqa: E402


class FakeModelCfg:
    def __init__(self, model, extra=None):
        self.model = model
        self.endpoint = "http://x/v1"
        self.temperature = 0.2
        self.max_tokens = 4096
        self.extra = extra or {}
        self.role = "verify"

    @property
    def family(self):
        from patchwing.config import family_of
        return family_of(self.model)


class FakeConfig:
    def __init__(self, patch_model, verify_model, verdict="sound", boom=False):
        self._m = {"patch": FakeModelCfg(patch_model),
                   "verify": FakeModelCfg(verify_model,
                                          extra={"chat_template_kwargs":
                                                 {"enable_thinking": False}})}
        self.verdict = verdict
        self.boom = boom
        self.pipeline = type("P", (), {"max_tokens_per_finding": 0,
                                       "max_usd_per_finding": 0})()

    def model(self, role):
        if role not in self._m:
            raise KeyError(role)
        return self._m[role]


class FakeClient:
    def __init__(self, cfg, verdict, boom):
        self.cfg = cfg
        self._v = verdict
        self._boom = boom
        from patchwing.models import Usage
        self.usage = Usage()
        self.last_raw_response = "{}"

    def chat_json(self, messages, required=()):
        if self._boom:
            raise RuntimeError("reviewer endpoint down")
        self.usage.prompt_tokens += 100
        self.usage.completion_tokens += 20
        return {"verdict": self._v, "reasons": ["stub"], "residual_risk": "none"}


class Ctx:
    def __init__(self, store, config):
        self.store = store
        self.workdir = tempfile.mkdtemp()
        self.config = config


class SeatTest(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db)
        self.f = self.store.add_finding(source="manual", repo_url="http://r",
                                        title="t", description="d")
        self._orig = stages._client

    def tearDown(self):
        stages._client = self._orig
        self.store.close()
        os.unlink(self.db)

    def _patch_client(self, cfg):
        def fake(ctx, role, finding=None, stage_name=""):
            return FakeClient(cfg.model(role), cfg.verdict, cfg.boom)
        stages._client = fake

    def test_records_reviewer_config_with_the_opinion(self):
        cfg = FakeConfig("moonshotai/Kimi-K3", "zai-org/GLM-5.2")
        self._patch_client(cfg)
        arts = stages._advisory_review(self.f, Ctx(self.store, cfg),
                                       "diff", "container said green")
        self.assertEqual(len(arts), 1)
        m = arts[0]["meta"]
        self.assertTrue(m["advisory"], "must be labelled advisory")
        rc = m["reviewer_config"]
        self.assertEqual(rc["model"], "zai-org/GLM-5.2")
        self.assertIn("chat_template_kwargs", rc["extra"],
                      "the flags that move the verdict must be recorded")

    def test_flags_same_family_as_weak_independence(self):
        cfg = FakeConfig("moonshotai/Kimi-K3", "moonshotai/Kimi-K2.7-Code")
        self._patch_client(cfg)
        m = stages._advisory_review(self.f, Ctx(self.store, cfg), "d", "r")[0]["meta"]
        self.assertTrue(m["same_family_as_fixer"])
        self.assertIn("WEAK", m["independence"])

    def test_different_family_is_reported_as_such(self):
        cfg = FakeConfig("moonshotai/Kimi-K3", "zai-org/GLM-5.2")
        self._patch_client(cfg)
        m = stages._advisory_review(self.f, Ctx(self.store, cfg), "d", "r")[0]["meta"]
        self.assertFalse(m["same_family_as_fixer"])

    def test_unsound_verdict_does_not_raise_or_block(self):
        """Advisory means advisory: a damning review still returns an artifact."""
        cfg = FakeConfig("moonshotai/Kimi-K3", "zai-org/GLM-5.2", verdict="unsound")
        self._patch_client(cfg)
        arts = stages._advisory_review(self.f, Ctx(self.store, cfg), "d", "r")
        self.assertEqual(arts[0]["meta"]["verdict"], "unsound")
        self.assertEqual(arts[0]["kind"], "review_advisory")

    def test_reviewer_failure_is_non_fatal(self):
        cfg = FakeConfig("moonshotai/Kimi-K3", "zai-org/GLM-5.2", boom=True)
        self._patch_client(cfg)
        arts = stages._advisory_review(self.f, Ctx(self.store, cfg), "d", "r")
        self.assertFalse(arts[0]["meta"]["available"])
        self.assertTrue(arts[0]["meta"]["advisory"])

    def test_no_reviewer_configured_is_silent(self):
        class NoVerify(FakeConfig):
            def model(self, role):
                if role == "verify":
                    raise KeyError("verify")
                return self._m["patch"]
        cfg = NoVerify("moonshotai/Kimi-K3", "unused")
        self.assertEqual(
            stages._advisory_review(self.f, Ctx(self.store, cfg), "d", "r"), [],
            "the reviewer is optional by design")

    def test_package_labels_the_opinion_advisory(self):
        cfg = FakeConfig("moonshotai/Kimi-K3", "zai-org/GLM-5.2")
        self._patch_client(cfg)
        ctx = Ctx(self.store, cfg)
        arts = stages._advisory_review(self.f, ctx, "d", "r")
        a = arts[0]
        self.store.add_artifact(self.f.id, a["kind"], "verify", a["content"],
                                a["meta"], "", a.get("model", ""))
        text = "\n".join(stages._review_lines(self.f, ctx))
        self.assertIn("advisory only", text.lower())
        self.assertIn("cannot change", text.lower())
        self.assertIn("zai-org/GLM-5.2", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
