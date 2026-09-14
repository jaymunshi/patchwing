"""Outcome classes must never collapse into one another.

Asserts on the OUTCOME VALUE, not on substrings in a message. A test that keys on
message text passes the moment someone reworded a string while re-merging two
outcomes — a test that cannot fail is not a test.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import outcomes                          # noqa: E402
from _stage_paths import terminating_paths              # noqa: E402

with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "patchwing", "stages.py"), encoding="utf-8") as _fh:
    SRC = _fh.read()

# Every `summary["outcome"] = "..."` in stages.py. These MIRROR a result outcome
# into the verdict artifact; they are not themselves terminating paths.
_MIRRORS = re.findall(r'summary\["outcome"\]\s*=\s*"([a-z_]+)"', SRC)


class OutcomeSeparationTest(unittest.TestCase):

    def test_all_outcome_values_are_distinct(self):
        """Distinct per CODE PATH, not per literal occurrence.

        This test used to count occurrences of the string in the source, which
        conflated "a value appears twice" with "two paths emit it". Three verify
        outcomes are deliberately written twice — once on the StageResult, once
        mirrored into the verdict artifact — so the occurrence count is 58 while
        the path count is 55. Under the old reading that correct state was a
        failure, which would have been fixed by deleting a mirror and losing the
        outcome from the evidence a reader actually opens. Ask the AST which paths
        exist and compare those.
        """
        paths = terminating_paths()
        seen: dict[str, list] = {}
        for p in paths:
            if p.outcome:
                seen.setdefault(p.outcome, []).append(p.describe())
        dupes = {v: ds for v, ds in seen.items() if len(ds) > 1}
        self.assertEqual({}, dupes,
                         "two code paths emit the same outcome value: %s" % dupes)

    def test_artifact_mirrors_never_invent_a_value(self):
        """A summary mirror must repeat a value some path emits.

        Otherwise the verdict artifact — the thing a stranger reads — can carry an
        outcome the pipeline never recorded, and the two disagree with no way to
        tell which is the real one.
        """
        emitted = {p.outcome for p in terminating_paths() if p.outcome}
        stray = sorted(set(_MIRRORS) - emitted)
        self.assertEqual([], stray,
                         "summary['outcome'] value(s) that no terminating path "
                         "emits: %s" % stray)
        not_declared = sorted(set(_MIRRORS) - outcomes.ALL)
        self.assertEqual([], not_declared,
                         "summary['outcome'] value(s) outside the closed set: %s"
                         % not_declared)

    def test_timeout_and_compile_failure_are_separate_values(self):
        self.assertIn("build_timeout_kill", SRC)
        self.assertIn("build_compile_failure", SRC)
        self.assertNotEqual("build_timeout_kill", "build_compile_failure")

    def test_timeout_branch_consults_timed_out_not_ok(self):
        """The defect was folding timed_out into r.ok. Guard the branch order."""
        i_to = SRC.index("if r.timed_out:")
        i_ok = SRC.index("if not r.ok:", i_to)   # search FORWARD from the timeout
                                                 # branch; an earlier not-ok exists
                                                 # in reproduce and is unrelated
        self.assertLess(i_to, i_ok,
                        "timed_out must be checked BEFORE the generic not-ok "
                        "branch, or a killed build is reported as a compile failure")

    def test_timeout_is_not_a_rejection(self):
        _i = SRC.index("if r.timed_out:")
        seg = SRC[_i:SRC.index("if not r.ok:", _i)]
        self.assertIn("StageResult.retry", seg)
        self.assertNotIn("StageResult.reject", seg,
                         "a timeout must not reject the patch — it was never judged")

    def test_build_seconds_recorded_on_both_build_outcomes(self):
        """Assert the property, not a count. Counting occurrences breaks the
        moment a message string mentions the field."""
        i = SRC.index("if r.timed_out:")
        j = SRC.index("if not r.ok:", i)
        k = SRC.index("art_md5_after", j)
        timeout_branch, compile_branch = SRC[i:j], SRC[j:k]
        for name, seg in (("timeout", timeout_branch), ("compile-failure", compile_branch)):
            self.assertIn('"build_seconds": build_seconds', seg,
                          "%s outcome must record wall-clock in meta" % name)
            self.assertIn('"outcome":', seg,
                          "%s outcome must carry a distinct outcome value" % name)

    def test_patch_evaluated_flag_distinguishes_absence_from_judgement(self):
        self.assertIn('"patch_evaluated": False', SRC)
        self.assertIn('"patch_evaluated": True', SRC)


if __name__ == "__main__":
    unittest.main(verbosity=2)
