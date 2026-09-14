"""A failing build is not automatically a rejection of the patch.

The 1076 CDATA run hit this: `arvo compile` in a prebuilt-only image failed with
`configure: error: cannot run C compiled programs`. The old code reported that as
`build_compile_failure` — "the patch is not valid code" — which is a verdict on
the fix drawn from a broken environment. Same shape as the timeout/compile
collapse and the exit-1/harness-fault collapse: absence wearing failure's face.

The classifier now demands POSITIVE evidence that the compiler saw the source.
Without it the build failure is `verify_build_harness_fault`, `patch_evaluated:
False`, `FAIL` (not `REJECT`). A rejection is a judgement; nothing judged
anything here.

Tests key on the OUTCOME VALUE, not on message substrings. A message reword can
never turn a harness fault into a rejection or vice versa if the outcome enum is
the assertion.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing.stages import _looks_like_compiler_verdict           # noqa: E402


class CompilerVerdictClassifierTest(unittest.TestCase):

    # -- environment failure, NOT a patch verdict -----------------------------

    def test_the_actual_1076_failure_reads_as_harness_fault(self):
        out = """configure: error: in `/src/libxml2':
configure: error: cannot run C compiled programs.
./configure: line 15297: python-config: command not found"""
        is_verdict, why = _looks_like_compiler_verdict(out)
        self.assertFalse(is_verdict,
                         "the actual 1076 environmental failure was being called "
                         "'the patch is not valid code'; guard the fix")
        self.assertIn("configure: error", why)

    def test_missing_toolchain_reads_as_harness_fault(self):
        for out in (
            "python-config: command not found",
            "autoreconf: command not found",
        ):
            with self.subTest(out=out):
                is_verdict, _ = _looks_like_compiler_verdict(out)
                self.assertFalse(is_verdict)

    def test_container_failure_reads_as_harness_fault(self):
        out = "podman: Error response from daemon: no space left"
        is_verdict, _ = _looks_like_compiler_verdict(out)
        self.assertFalse(is_verdict)

    def test_empty_output_reads_as_harness_fault(self):
        """No output at all is not evidence the patch is wrong."""
        for out in ("", None, "\n\n"):
            with self.subTest(out=repr(out)):
                is_verdict, _ = _looks_like_compiler_verdict(out)
                self.assertFalse(is_verdict)

    # -- compiler DID judge the patch — legitimate reject ---------------------

    def test_source_level_compile_error_is_a_verdict(self):
        out = "SAX2.c:449:5: error: expected ';' before 'memset'\ncompilation terminated."
        is_verdict, why = _looks_like_compiler_verdict(out)
        self.assertTrue(is_verdict)
        self.assertIn("error:", why)

    def test_link_error_is_a_verdict(self):
        out = "/usr/bin/ld: cannot find -lfoo\ncollect2: error: ld returned 1 exit status"
        is_verdict, _ = _looks_like_compiler_verdict(out)
        self.assertTrue(is_verdict)

    def test_undefined_reference_is_a_verdict(self):
        out = "SAX2.o: undefined reference to `not_a_real_function`"
        is_verdict, _ = _looks_like_compiler_verdict(out)
        self.assertTrue(is_verdict)

    def test_implicit_declaration_is_a_verdict(self):
        out = "SAX2.c:449:5: warning: implicit declaration of function 'memset'"
        is_verdict, _ = _looks_like_compiler_verdict(out)
        self.assertTrue(is_verdict)

    # -- precedence: environment wins over compiler-shaped noise --------------

    def test_environment_error_wins_over_compile_error_noise(self):
        """Autotools logs often quote earlier compiler errors while ultimately
        failing on the environment. If configure: error: is present, that IS the
        failure, and grepping deeper for '.c:N: error:' would misclassify."""
        out = """SAX2.c:1:1: error: something
... (much noise)
configure: error: cannot run C compiled programs.
"""
        is_verdict, why = _looks_like_compiler_verdict(out)
        self.assertFalse(is_verdict,
                         "environment failure precedence must be strict — a run "
                         "that could not build cannot judge a patch even if it "
                         "quoted a compile error somewhere in its log")


if __name__ == "__main__":
    unittest.main(verbosity=2)
