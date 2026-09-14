"""A stage that RAISES must be named, bounded, and never mistaken for a verdict.

Before this, a raise inside a stage became STATE_PENDING with a traceback and no
outcome, retried to max_attempts, and finally STATE_FAILED — the same shape as a run
that was judged and found wanting. Three properties are asserted here, behaviourally
against the real Runner and the real store, because the defect was invisible to
reasoning and only appeared when real exceptions were run through real code:

  A. NAMED     — every one of these paths records an outcome from the closed set,
                 so §9a's guarantee no longer stops at the boundary of the catch.
  B. BOUNDED   — at most ONE retry, and only for classes where a second attempt
                 could plausibly succeed. Everything else terminates on the first
                 raise. Each retry here costs a rebuild of a 6.57 GB tree, and most
                 of what lands here is deterministic at the same ceiling.
  D. NOT A VERDICT — patch_evaluated is False on every one of these paths and the
                 terminal state is FAILED, never REJECTED. An infrastructure failure
                 must never be reportable as a verdict on the patch. This is the
                 fourth instance of that one disease: timeout/compile,
                 exit-1/harness-fault, rollback-satisfied-by-malfunction, and this.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import models as models_mod                # noqa: E402
from patchwing import outcomes                            # noqa: E402
from patchwing import sandbox as sandbox_mod              # noqa: E402
from patchwing import stages as stages_mod                # noqa: E402
from patchwing.runner import Runner                       # noqa: E402
from patchwing.store import (STATE_FAILED, STATE_PENDING,  # noqa: E402
                             STATE_REJECTED, Store)


class HarnessFailureTest(unittest.TestCase):

    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.conn.close)
        self.runner = Runner(self.store, verbose=False, max_attempts=3)
        self._n = 0

    def _raise_stage(self, exc):
        """Register a stage that raises `exc`, and return a fresh finding on it."""
        self._n += 1
        name = f"t_raise_{self._n}"

        def _stage(f, ctx):
            raise exc
        stages_mod._REGISTRY[name] = _stage
        self.addCleanup(stages_mod._REGISTRY.pop, name, None)
        return self.store.add_finding(source="t", repo_url="http://x.invalid",
                                      stage=name)

    def _meta(self, finding_id):
        art = self.store.latest_artifact(finding_id, "harness_failure")
        self.assertIsNotNone(art, "no harness_failure artifact was recorded — the "
                                  "outcome is unrecoverable from the DB")
        return json.loads(art["meta"])

    # -- A: named ---------------------------------------------------------

    def test_a_raise_records_a_declared_outcome(self):
        f = self._raise_stage(KeyError("n_files"))
        self.runner._advance(f)
        meta = self._meta(f.id)
        self.assertIn(meta["outcome"], outcomes.ALL)
        self.assertEqual(outcomes.INFRASTRUCTURE_FAILURE, meta["outcome"])

    def test_a_the_traceback_is_still_attached(self):
        f = self._raise_stage(KeyError("n_files"))
        self.runner._advance(f)
        art = self.store.latest_artifact(f.id, "harness_failure")
        self.assertIn("KeyError", art["content"],
                      "the traceback must survive — naming the failure is not a "
                      "reason to stop showing it")

    # -- B: bounded -------------------------------------------------------

    def test_b_non_retryable_class_terminates_on_the_first_raise(self):
        for exc in (KeyError("k"), AttributeError("a"), TypeError("t"),
                    MemoryError(), OSError(28, "No space left on device")):
            with self.subTest(exc=type(exc).__name__):
                f = self._raise_stage(exc)
                self.runner._advance(f)
                got = self.store.get(f.id)
                self.assertEqual(STATE_FAILED, got.state)
                self.assertEqual(1, got.attempts,
                                 "a retry that cannot succeed must not be spent")
                self.assertFalse(self._meta(f.id)["retry_granted"])

    def test_b_retryable_class_gets_exactly_one_retry(self):
        f = self._raise_stage(sandbox_mod.SandboxError("container will not start"))
        self.runner._advance(f)
        got = self.store.get(f.id)
        self.assertEqual(STATE_PENDING, got.state)
        self.assertEqual(1, got.attempts)
        meta = self._meta(f.id)
        self.assertEqual(outcomes.HARNESS_RAISED_RETRYING, meta["outcome"])
        self.assertTrue(meta["retry_granted"])

    def test_b_second_identical_failure_terminates_and_says_so(self):
        """C: if the second attempt fails the same way, terminate as an
        infrastructure failure — and record that it failed the same way."""
        exc = sandbox_mod.SandboxError("container will not start")
        f = self._raise_stage(exc)
        self.runner._advance(f)                     # attempt 1 -> retry granted
        self.runner._advance(self.store.get(f.id))  # attempt 2 -> same failure
        got = self.store.get(f.id)
        self.assertEqual(STATE_FAILED, got.state)
        meta = self._meta(f.id)
        self.assertEqual(outcomes.INFRASTRUCTURE_FAILURE, meta["outcome"])
        self.assertTrue(meta["same_failure_as_previous_attempt"],
                        "attempt 2 failing the same way is the finding — record it")

    def test_b_never_retry_beats_retryable_superclass(self):
        """AuthError subclasses ModelError. A 401 does not become a 200 twice."""
        f = self._raise_stage(models_mod.AuthError("401 unauthorized"))
        self.runner._advance(f)
        self.assertEqual(STATE_FAILED, self.store.get(f.id).state)
        self.assertFalse(self._meta(f.id)["retry_granted"])

    def test_b_a_retryable_class_still_only_ever_gets_one(self):
        """Bounded at ONE, not at max_attempts. The runner's default is 3."""
        f = self._raise_stage(sqlite3.OperationalError("database is locked"))
        for _ in range(4):
            cur = self.store.get(f.id)
            if cur.state == STATE_FAILED:
                break
            self.runner._advance(cur)
        got = self.store.get(f.id)
        self.assertEqual(STATE_FAILED, got.state)
        self.assertLessEqual(got.attempts, 2,
                             "at most one retry means at most two attempts")

    # -- D: never a verdict on the patch ----------------------------------

    def test_d_patch_evaluated_is_false_on_every_harness_path(self):
        for exc in (KeyError("k"), MemoryError(),
                    sandbox_mod.SandboxError("no container"),
                    models_mod.AuthError("401"),
                    sqlite3.OperationalError("locked")):
            with self.subTest(exc=type(exc).__name__):
                f = self._raise_stage(exc)
                self.runner._advance(f)
                self.assertIs(False, self._meta(f.id)["patch_evaluated"],
                              "an infrastructure failure must never be reportable "
                              "as a verdict on the patch")

    def test_d_a_harness_failure_is_never_a_rejection(self):
        """REJECTED means judged and found wanting. Nothing here judged anything."""
        for exc in (KeyError("k"), sandbox_mod.SandboxError("no container"),
                    MemoryError()):
            with self.subTest(exc=type(exc).__name__):
                f = self._raise_stage(exc)
                self.runner._advance(f)
                self.runner._advance(self.store.get(f.id))
                self.assertNotEqual(STATE_REJECTED, self.store.get(f.id).state)


if __name__ == "__main__":
    unittest.main(verbosity=2)
