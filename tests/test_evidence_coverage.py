"""THE EVIDENCE GUARD. A verdict on something that ran must attach what it ran.

The §9a guard asks whether every terminating path SAYS what happened. This one asks
whether every path that pronounces on executed code SHOWS it. They are the same
shape deliberately: a property over all paths, enforced by a parser, failing with
line numbers, so path 56 cannot arrive unguarded.

The defect this was written for: ``reproduce`` rejected with
``reproduce_did_not_reproduce`` — "the vulnerability does not reproduce, so there is
nothing to fix" — and returned WITHOUT the reproducer output. That is the single
most checkable claim the stage makes, thrown away at the moment it is asserted, on
the stage a run reaches first. A rejection with no evidence attached is the exact
failure this project exists to eliminate; it was sitting inside the project.

Scanning for it found five more, including two in ``verify``: ``build_compile_failure``
REJECTS the fix-writer's patch as "not valid code" while attaching no build log, and
``build_timeout_kill`` recorded a duration but not the log it timed out producing.

The rule is mechanical, not a judgement call per path: a terminating path lexically
after a ``.run(...)`` in its own function must pass ``artifacts=``. It over-reports
rather than under-reports (see ``_first_execution_line``) — a false positive costs a
human one look, a false negative ships an unsupported verdict.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _stage_paths import terminating_paths              # noqa: E402


class EvidenceCoverageTest(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.paths = terminating_paths()

    def test_the_scanner_sees_execution(self):
        """If nothing were ever classified post-execution the guard below would
        pass vacuously, which is the failure mode of every check that greps."""
        post = [p for p in self.paths if p.post_execution]
        self.assertGreater(len(post), 5,
                           "no post-execution paths found — the execution scanner "
                           "is broken and the evidence guard is now vacuous")

    def test_every_post_execution_path_attaches_evidence(self):
        naked = [p for p in self.paths
                 if p.post_execution and not p.has_artifacts]
        self.assertEqual(
            [], naked,
            "%d path(s) pronounce a verdict on executed code but attach no "
            "evidence — the justification is discarded at the moment it is "
            "asserted:\n%s"
            % (len(naked),
               "\n".join(f"  {p.describe()}  [{p.outcome}]" for p in naked)))

    def test_rejections_and_failures_after_execution_are_covered(self):
        """Stated separately from the general rule because it is the claim that
        matters: a REJECT or FAIL is an adverse verdict on someone's work, and an
        adverse verdict is the one a reader is most entitled to check."""
        adverse = [p for p in self.paths
                   if p.post_execution and p.kind in ("reject", "fail")
                   and not p.has_artifacts]
        self.assertEqual(
            [], adverse,
            "adverse verdict(s) with no evidence attached:\n%s"
            % "\n".join(f"  {p.describe()}  [{p.outcome}]" for p in adverse))


if __name__ == "__main__":
    unittest.main(verbosity=2)
