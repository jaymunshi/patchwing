"""Tests for search/replace editing.

The properties that matter: never apply an ambiguous edit, never silently apply at
the wrong place, and make every refusal a harness outcome rather than a verdict on
the fix.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import edit  # noqa: E402

SRC = """int a(void) {
    if (ret == NULL)
        return -1;
    return 0;
}

int b(void) {
    if (ret == NULL)
        return -1;
    return 1;
}
"""

BLOCK = """Some prose from the model.

<<<<<<< SEARCH
int a(void) {
=======
int a(int x) {
>>>>>>> REPLACE
"""


class ParseTest(unittest.TestCase):
    def test_parses_a_block_among_prose(self):
        b = edit.parse(BLOCK)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0].search, "int a(void) {")
        self.assertEqual(b[0].replace, "int a(int x) {")

    def test_parses_multiple_blocks(self):
        t = BLOCK + """
<<<<<<< SEARCH
    return 1;
=======
    return 2;
>>>>>>> REPLACE
"""
        self.assertEqual(len(edit.parse(t)), 2)

    def test_tolerates_varied_marker_lengths(self):
        t = "<<<<<<<< SEARCH\nfoo\n========\nbar\n>>>>>>>> REPLACE"
        self.assertEqual(len(edit.parse(t)), 1)

    def test_no_blocks_returns_empty(self):
        self.assertEqual(edit.parse("just prose, no blocks"), [])

    def test_empty_search_is_dropped(self):
        self.assertEqual(edit.parse("<<<<<<< SEARCH\n\n=======\nx\n>>>>>>> REPLACE"), [])

    def test_edits_wrong_type_raises_typed_error(self):
        """A schema violation (list/dict/int) must become a typed error the
        patch stage can catch, not a TypeError crash the runner sees as
        infrastructure. Each of the plausible non-string types Kimi/GLM/others
        might return under a prompt that reads as invitation to a collection."""
        with self.assertRaises(edit.EditsWrongTypeError) as cm:
            edit.parse([])
        self.assertEqual(cm.exception.actual_type, "list")

        with self.assertRaises(edit.EditsWrongTypeError) as cm:
            edit.parse({})
        self.assertEqual(cm.exception.actual_type, "dict")

        with self.assertRaises(edit.EditsWrongTypeError) as cm:
            edit.parse(0)
        self.assertEqual(cm.exception.actual_type, "int")

    def test_edits_none_still_treated_as_empty(self):
        """Backward compat: callers pass `.get('edits')` without a default and
        rely on None → []."""
        self.assertEqual(edit.parse(None), [])

    def test_edits_empty_string_still_treated_as_empty(self):
        self.assertEqual(edit.parse(""), [])

    def test_edits_wrong_type_is_a_subclass_of_edit_error(self):
        """Existing callers that catch EditError generically must still see it —
        the subclass is for callers that want to distinguish, not a way for
        this to slip past defensive catches."""
        try:
            edit.parse([])
        except edit.EditError as e:
            self.assertIsInstance(e, edit.EditsWrongTypeError)


class ApplyTest(unittest.TestCase):
    def test_applies_a_unique_block(self):
        r = edit.apply(SRC, edit.parse(BLOCK))
        self.assertEqual(r.applied, 1)
        self.assertIn("int a(int x) {", r.text)
        self.assertIn("int b(void) {", r.text, "unrelated code must be untouched")

    def test_rejects_ambiguous_search(self):
        """The whole point: 'if (ret == NULL)' appears twice here and in real C
        appears everywhere. First-match-wins would patch the wrong function."""
        blocks = [edit.Block(search="    if (ret == NULL)", replace="    if (!ret)")]
        with self.assertRaises(edit.EditError) as cm:
            edit.apply(SRC, blocks)
        self.assertIn("occurs 2 times", str(cm.exception))
        self.assertIn("ambiguous", str(cm.exception))

    def test_ambiguous_search_is_a_typed_subclass_with_fields(self):
        """The caller (stages.patch) catches AmbiguousSearchError specifically to
        retry the model with a targeted note. That is only possible if the
        exception is a subclass and carries the fields the retry note needs —
        block index, total blocks, match count, search text. String-matching
        the message would be brittle and re-open the same hole that having a
        closed-set outcome closes elsewhere."""
        blocks = [edit.Block(search="    if (ret == NULL)", replace="    if (!ret)")]
        with self.assertRaises(edit.AmbiguousSearchError) as cm:
            edit.apply(SRC, blocks)
        err = cm.exception
        self.assertIsInstance(err, edit.EditError,
                              "AmbiguousSearchError must remain an EditError so "
                              "the existing catch-all keeps working for callers "
                              "that don't care about the distinction")
        self.assertEqual(err.block_index, 1)
        self.assertEqual(err.total_blocks, 1)
        self.assertEqual(err.match_count, 2)
        self.assertEqual(err.search, "    if (ret == NULL)")

    def test_rejects_missing_search(self):
        blocks = [edit.Block(search="int nonexistent(void)", replace="x")]
        with self.assertRaises(edit.EditError) as cm:
            edit.apply(SRC, blocks)
        self.assertIn("not found", str(cm.exception))

    def test_whitespace_drift_gets_a_specific_hint(self):
        """A bare 'not found' is unactionable; naming whitespace is."""
        blocks = [edit.Block(search="int  a(void)  {", replace="int a(int x) {")]
        with self.assertRaises(edit.EditError) as cm:
            edit.apply(SRC, blocks)
        self.assertIn("whitespace differs", str(cm.exception))

    def test_no_blocks_is_an_error(self):
        with self.assertRaises(edit.EditError):
            edit.apply(SRC, [])

    def test_noop_replacement_is_rejected(self):
        blocks = [edit.Block(search="int a(void) {", replace="int a(void) {")]
        with self.assertRaises(edit.EditError) as cm:
            edit.apply(SRC, blocks)
        self.assertIn("unchanged", str(cm.exception))

    def test_sequential_blocks_see_earlier_edits(self):
        blocks = [edit.Block(search="int a(void) {", replace="int a(int x) {"),
                  edit.Block(search="int a(int x) {", replace="int a(long x) {")]
        r = edit.apply(SRC, blocks)
        self.assertEqual(r.applied, 2)
        self.assertIn("int a(long x) {", r.text)

    def test_deletion_block(self):
        blocks = [edit.Block(search="    return 0;\n", replace="")]
        r = edit.apply(SRC, blocks)
        self.assertTrue(blocks[0].is_deletion)
        self.assertNotIn("return 0;", r.text)


class WindowTest(unittest.TestCase):
    def test_window_centres_on_anchor(self):
        text, lo, hi = edit.window(SRC, ["int b(void)"], radius=2)
        self.assertIn("int b(void)", text)
        self.assertLess(hi - lo, len(SRC.splitlines()))

    def test_window_without_anchor_falls_back_to_head(self):
        text, lo, hi = edit.window(SRC, ["nothing here"], radius=3)
        self.assertEqual(lo, 1)
        self.assertIn("int a(void)", text)

    def test_window_reports_its_line_range(self):
        _t, lo, hi = edit.window(SRC, ["int b(void)"], radius=1)
        self.assertGreaterEqual(lo, 1)
        self.assertGreaterEqual(hi, lo)

    def test_empty_source_is_safe(self):
        self.assertEqual(edit.window("", ["x"]), ("", 0, 0))


class DiffTest(unittest.TestCase):
    def test_renders_unified_diff_for_the_package(self):
        r = edit.apply(SRC, edit.parse(BLOCK))
        d = edit.to_unified_diff("SAX2.c", SRC, r.text)
        self.assertIn("--- a/SAX2.c", d)
        self.assertIn("-int a(void) {", d)
        self.assertIn("+int a(int x) {", d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
