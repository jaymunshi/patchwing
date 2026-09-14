"""§6b′ classifier — the MSan-friendly decision table.

The prior code decided the four states by `returncode + marker + token`. Under
that rule, an MSan reproducer with `abort_on_error=0` — the supported,
documented mode used across the ARVO corpus — was labelled ``harness_fault``
because "the exit code and the output disagree". That was wrong. libFuzzer
exits 0 after MSan reports without abort. A real red was being called a
harness bug, corrupting every iteration signal on every MSan target.

New rule: marker + DEDUP_TOKEN identity decide. Exit code is secondary, read
only when there is no marker. These tests are the assertion that keeps that
true — a regression here means MSan reds are getting mislabelled again.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import states                              # noqa: E402


# Anchors for a real 1076 MSan reproducer output. The pristine token is the
# CRASH-SITE token (first DEDUP_TOKEN in the trace), which is what
# `dedup_token()` returns and what gets recorded when the wall is frozen.
_PRISTINE_TOKEN = "xmlNextChar--xmlParseCharRef--xmlParseAttValueComplex"
_ORIGIN_TOKEN = "malloc--xmlBufCreate--xmlSwitchInputEncodingInt"

_MSAN_RED_EXIT_ZERO = f"""==6==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x9d3e23 in xmlNextChar /src/libxml2/parserInternals.c:526:13
DEDUP_TOKEN: {_PRISTINE_TOKEN}
  Uninitialized value was created by a heap allocation
    #1 0x846e3d in xmlBufCreate /src/libxml2/buf.c:137:32
DEDUP_TOKEN: {_ORIGIN_TOKEN}
SUMMARY: MemorySanitizer: use-of-uninitialized-value \
/src/libxml2/parserInternals.c:526:13 in xmlNextChar
Exiting
"""

_MSAN_RED_EXIT_77 = _MSAN_RED_EXIT_ZERO   # same output; different exit


class DecisionTableTest(unittest.TestCase):
    """One test per row of the decision table. Failure mode is named in the
    assertion message so a regression tells you exactly what fused with what."""

    # ---- marker present + token matches -> CONFIRMED_RED regardless of exit --

    def test_msan_exit_zero_with_matching_token_is_confirmed_red(self):
        """THE bug this fix exists for. MSan `abort_on_error=0` → exit 0
        with a real MSan report. Must NOT be harness_fault."""
        r = states.classify("sanitizer", returncode=0, output=_MSAN_RED_EXIT_ZERO,
                            pristine_token=_PRISTINE_TOKEN)
        self.assertEqual(states.CONFIRMED_RED, r["state"],
                         "MSan exit-0 + marker + token match must be "
                         "confirmed_red — exit code cannot override the "
                         "sanitizer report")
        self.assertTrue(r["token_matches_pristine"])
        self.assertTrue(states.is_red(r))
        self.assertFalse(states.is_green(r))

    def test_msan_exit_nonzero_with_matching_token_is_confirmed_red(self):
        r = states.classify("sanitizer", returncode=77, output=_MSAN_RED_EXIT_77,
                            pristine_token=_PRISTINE_TOKEN)
        self.assertEqual(states.CONFIRMED_RED, r["state"])

    def test_asan_segv_exit_139_with_matching_token_is_confirmed_red(self):
        """Same rule for ASan. Some ASan builds exit 139 on SIGSEGV during
        symbolization. Marker + matching token still wins."""
        asan_out = (
            "==1==ERROR: AddressSanitizer: global-buffer-overflow\n"
            "DEDUP_TOKEN: token-A\n"
            "SUMMARY: AddressSanitizer: global-buffer-overflow test.c:42 in foo\n")
        r = states.classify("sanitizer", returncode=139, output=asan_out,
                            pristine_token="token-A")
        self.assertEqual(states.CONFIRMED_RED, r["state"])

    # ---- marker present + token mismatches -> DIFFERENT_BUG ------------------

    def test_marker_with_different_token_is_different_bug_at_exit_zero(self):
        """Iteration 2 shape: MSan fires but a DIFFERENT crash than pristine.
        Exit 0 must not push this to harness_fault."""
        r = states.classify("sanitizer", returncode=0, output=_MSAN_RED_EXIT_ZERO,
                            pristine_token="totally-different-token")
        self.assertEqual(states.DIFFERENT_BUG, r["state"])
        self.assertFalse(r["token_matches_pristine"])

    def test_marker_with_different_token_is_different_bug_at_nonzero_exit(self):
        r = states.classify("sanitizer", returncode=77, output=_MSAN_RED_EXIT_ZERO,
                            pristine_token="totally-different-token")
        self.assertEqual(states.DIFFERENT_BUG, r["state"])

    def test_marker_without_extractable_token_is_different_bug(self):
        out = ("SUMMARY: MemorySanitizer: use-of-uninitialized-value "
               "/lib/glibc.so in memcpy\n")
        # SUMMARY parses to a synthetic 'summary:...' token. Must not match a
        # concrete pristine token.
        r = states.classify("sanitizer", returncode=0, output=out,
                            pristine_token=_PRISTINE_TOKEN)
        self.assertEqual(states.DIFFERENT_BUG, r["state"])

    # ---- no marker + exit 0 -> CONFIRMED_GREEN -------------------------------

    def test_clean_exit_no_marker_is_confirmed_green(self):
        r = states.classify("sanitizer", returncode=0, output="all good, no crash",
                            pristine_token=_PRISTINE_TOKEN)
        self.assertEqual(states.CONFIRMED_GREEN, r["state"])
        self.assertTrue(states.is_green(r))
        self.assertFalse(states.is_red(r))

    def test_clean_exit_empty_output_is_confirmed_green(self):
        r = states.classify("sanitizer", returncode=0, output="",
                            pristine_token=_PRISTINE_TOKEN)
        self.assertEqual(states.CONFIRMED_GREEN, r["state"])

    # ---- no marker + non-zero exit -> HARNESS_FAULT --------------------------

    def test_the_1237_case_exit_1_no_marker_is_harness_fault(self):
        """Exit 1 with no sanitizer output is what motivated §6b′ in the first
        place. Missing mount, shell error, container-never-started — none of
        them are the bug reproducing."""
        r = states.classify("sanitizer", returncode=1, output="podman: no such file",
                            pristine_token=_PRISTINE_TOKEN)
        self.assertEqual(states.HARNESS_FAULT, r["state"])
        self.assertFalse(states.is_red(r))

    def test_segv_no_marker_is_harness_fault(self):
        """MSan runtime flakiness: SEGV at startup before the sanitizer can
        report. Not evidence of anything about the bug."""
        r = states.classify("sanitizer", returncode=139, output="Segmentation fault (core dumped)",
                            pristine_token=_PRISTINE_TOKEN)
        self.assertEqual(states.HARNESS_FAULT, r["state"])

    def test_leak_only_output_dropped_from_marker_regex(self):
        """LeakSanitizer is deliberately NOT in the marker regex. A leak-only
        report with non-zero exit falls through to harness_fault, which is the
        conservative reading (Leak fires at exit on unrelated leaks and would
        manufacture false reds)."""
        r = states.classify("sanitizer", returncode=1,
                            output="==1==ERROR: LeakSanitizer: detected leaks",
                            pristine_token=_PRISTINE_TOKEN)
        self.assertEqual(states.HARNESS_FAULT, r["state"])

    # ---- timeout is its own class -------------------------------------------

    def test_timeout_is_always_harness_fault(self):
        r = states.classify("sanitizer", returncode=0, output=_MSAN_RED_EXIT_ZERO,
                            pristine_token=_PRISTINE_TOKEN, timed_out=True)
        self.assertEqual(states.HARNESS_FAULT, r["state"])
        self.assertIn("timed out", r["why"])

    # ---- no pristine yet: first reproduce sets it ---------------------------

    def test_first_reproduce_with_marker_and_no_pristine_is_confirmed_red(self):
        """The very first reproduce runs BEFORE the wall is frozen — there is
        no pristine token to compare against. Marker + extractable token must
        still count as red; that is how the pristine gets recorded."""
        r = states.classify("sanitizer", returncode=0, output=_MSAN_RED_EXIT_ZERO,
                            pristine_token="")
        self.assertEqual(states.CONFIRMED_RED, r["state"])
        # `dedup_token()` picks the FIRST DEDUP_TOKEN — the crash-site token.
        self.assertEqual(_PRISTINE_TOKEN, r["dedup_token"])

    # ---- meta: is_red / is_green are strict ---------------------------------

    def test_is_red_and_is_green_are_strict(self):
        different = states.classify("sanitizer", returncode=0, output=_MSAN_RED_EXIT_ZERO,
                                    pristine_token="other")
        self.assertFalse(states.is_red(different))
        self.assertFalse(states.is_green(different))


if __name__ == "__main__":
    unittest.main(verbosity=2)
