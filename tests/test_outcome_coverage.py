"""THE GUARD. Every terminating path carries a declared, unique outcome value.

This is the fix; the labelling is the cleanup. Before this file existed, 53 of 55
terminating paths carried no outcome value, and the way that was discovered was a
human reading the file — which is exactly the method that had already mis-read it
twice. The remedy for a wrong reading is an assertion that fails, not a closer read.

What it asserts, and why each one is load-bearing:

  1. COVERAGE   — no path may be unlabelled. Path 56, added next month, arrives
                  unlabelled and this fails. That is the whole point: the guard has
                  to be the thing that notices, because nobody re-audits 55 paths.
  2. MEMBERSHIP — every value is in the closed set. A typo is a FAILURE, not a new
                  category, and this is where that becomes true.
  3. UNIQUENESS — no two paths share a value. Two paths with one value is two
                  distinct ways of stopping that a reader cannot tell apart, which
                  is the (a)/(b) collapse one layer up.
  4. NO SLACK   — every declared constant is used. Holds the set and the path list
                  equal from BOTH directions, so a renamed path cannot leave a
                  stale constant behind that still satisfies MEMBERSHIP.
  5. SCOPE      — stages.py is the only file constructing results, so a guard that
                  reads one file is reading all of them.

A note on how this was run: the guard was executed and SEEN TO FAIL (55 paths, 53
unlabelled) before any path was labelled, then seen to pass after. A guard that has
never been observed failing is not a guard — it is a comment that takes time to run.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import outcomes                          # noqa: E402
from _stage_paths import (construction_sites,           # noqa: E402
                          outcome_literals_in_package,
                          terminating_paths)


class OutcomeCoverageTest(unittest.TestCase):

    def setUp(self):
        # A guard whose failure message is truncated makes the reader go looking
        # for the paths it already knows about. Print all of them.
        self.maxDiff = None
        self.paths = terminating_paths()

    def test_there_are_paths_to_check(self):
        """A walker that silently found nothing would make every test below pass."""
        self.assertGreater(len(self.paths), 40,
                           "the AST walker found almost no terminating paths — it is "
                           "broken, and every other assertion here is now vacuous")

    def test_every_terminating_path_carries_an_outcome(self):
        naked = [p for p in self.paths if p.outcome is None and not p.dynamic]
        self.assertEqual(
            [], naked,
            "%d of %d terminating path(s) carry no outcome value:\n%s"
            % (len(naked), len(self.paths),
               "\n".join("  " + p.describe() for p in naked)))

    def test_no_outcome_is_computed_at_runtime(self):
        """A dynamic value cannot be checked against the closed set by reading the
        source, so it re-opens the hole this guard closes."""
        dyn = [p for p in self.paths if p.dynamic]
        self.assertEqual([], dyn,
                         "outcome must be a literal from patchwing.outcomes:\n%s"
                         % "\n".join("  " + p.describe() for p in dyn))

    def test_every_outcome_is_in_the_closed_set(self):
        stray = sorted({p.outcome for p in self.paths
                        if p.outcome and p.outcome not in outcomes.ALL})
        self.assertEqual([], stray,
                         "outcome value(s) not declared in patchwing/outcomes.py "
                         "(a typo, or a category invented at the call site): %s"
                         % stray)

    def test_no_two_paths_share_an_outcome(self):
        seen: dict[str, list] = {}
        for p in self.paths:
            if p.outcome:
                seen.setdefault(p.outcome, []).append(p)
        dupes = {v: ps for v, ps in seen.items() if len(ps) > 1}
        self.assertEqual(
            {}, dupes,
            "outcome value(s) emitted by more than one path — two ways of stopping "
            "that a reader cannot tell apart:\n%s"
            % "\n".join("  %s\n%s" % (v, "\n".join("    " + p.describe() for p in ps))
                        for v, ps in sorted(dupes.items())))

    def test_no_declared_outcome_is_unused(self):
        """Both directions, across the whole package.

        Stage paths are not the only recorder: runner._advance records an outcome
        when a stage RAISES, which is the one case that never builds a StageResult.
        Scoping this to stage paths alone would report those constants as unused and
        make deleting them look like the fix.
        """
        used = {p.outcome for p in self.paths if p.outcome}
        for names in outcome_literals_in_package().values():
            used |= names
        unused = sorted(outcomes.ALL - used)
        self.assertEqual([], unused,
                         "declared but unreachable outcome(s) — the closed set has "
                         "drifted from the paths it describes: %s" % unused)

    def test_every_outcome_recorded_anywhere_is_declared(self):
        """Membership, extended past stages.py for the same reason as above."""
        stray = {}
        for fname, names in outcome_literals_in_package().items():
            bad = sorted(n for n in names if n not in outcomes.ALL
                         and not n.isupper())   # bare constants resolve at runtime
            if bad:
                stray[fname] = bad
        self.assertEqual({}, stray,
                         "outcome value(s) recorded but not declared: %s" % stray)

    def test_stages_is_the_only_construction_site(self):
        self.assertEqual(
            ["stages.py"], construction_sites(),
            "StageResult is built outside stages.py, so this guard no longer covers "
            "every terminating path")


class ClosedSetTest(unittest.TestCase):
    """The set itself must behave like a closed set."""

    def test_validate_accepts_a_member(self):
        self.assertEqual(outcomes.VERIFY_GREEN_ROLLBACK_RED,
                         outcomes.validate(outcomes.VERIFY_GREEN_ROLLBACK_RED))

    def test_validate_rejects_a_typo(self):
        with self.assertRaises(outcomes.UnknownOutcome):
            outcomes.validate("verify_geen")

    def test_the_milestone_outcome_exists(self):
        """Named explicitly. The milestone's terminal claim is the FULL CHAIN —
        red -> patch -> green -> rollback -> red again — not "the reproducer
        passed". A bare `verify_green` was deliberately retired when the rollback
        leg landed, so that a half-proved result cannot wear the whole result's
        name."""
        self.assertIn(outcomes.VERIFY_GREEN_ROLLBACK_RED, outcomes.ALL)
        self.assertFalse(hasattr(outcomes, "VERIFY_GREEN"),
                         "a bare verify_green is back — green without a rollback "
                         "reading is half a claim, not a terminal one")


class RunnerDoesNotSwallowContractViolationsTest(unittest.TestCase):
    """The runner converts any exception to a RETRY. That is right for a transient
    and wrong for an undeclared outcome, which would then present as a flaky stage
    and be recorded as a generic failure after burning the attempt limit. Assert the
    exemption behaviourally — reading the source for a `raise` proves only that the
    word is present.
    """

    def _runner_with(self, stage_name, fn):
        from patchwing import stages as stages_mod
        from patchwing.runner import Runner
        from patchwing.store import Store

        stages_mod._REGISTRY[stage_name] = fn
        self.addCleanup(stages_mod._REGISTRY.pop, stage_name, None)
        store = Store(":memory:")
        self.addCleanup(store.conn.close)
        f = store.add_finding(source="test", repo_url="http://example.invalid",
                              stage=stage_name)
        return Runner(store, verbose=False), f

    def test_an_undeclared_outcome_escapes_the_runner(self):
        def bad_stage(f, ctx):
            return stages_result_with_bad_outcome()

        def stages_result_with_bad_outcome():
            from patchwing.stages import StageResult
            return StageResult.ok("x", meta={"outcome": "verify_geen"})

        runner, finding = self._runner_with("t_bad_outcome", bad_stage)
        with self.assertRaises(outcomes.UnknownOutcome):
            runner._advance(finding)

    def test_an_ordinary_exception_is_still_a_retry(self):
        """The exemption must be narrow. If it widened to all exceptions, a genuine
        transient would stop the run instead of being retried."""
        def boom(f, ctx):
            raise RuntimeError("transient")

        runner, finding = self._runner_with("t_boom", boom)
        runner._advance(finding)          # must NOT raise
        refreshed = runner.store.get(finding.id)
        self.assertEqual(1, refreshed.attempts,
                         "an ordinary exception must still be retried")


if __name__ == "__main__":
    unittest.main(verbosity=2)
