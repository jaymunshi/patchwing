#!/usr/bin/env python3
"""
The project's own test suite. A patch must keep every one of these green —
this is what stops a "fix" that simply breaks the feature.

Stdlib unittest, no dependencies.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from notes.store import NoteStore  # noqa: E402


class TestNoteStore(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="patchwing-test-")
        self.store = NoteStore(os.path.join(self.root, "notes"))

    def test_write_then_read(self):
        self.store.write_note("a.txt", "hello")
        self.assertEqual(self.store.read_note("a.txt"), "hello")

    def test_unicode_roundtrip(self):
        self.store.write_note("u.txt", "héllo — नमस्ते")
        self.assertEqual(self.store.read_note("u.txt"), "héllo — नमस्ते")

    def test_nested_notes_are_supported(self):
        # Subdirectories are a legitimate feature; a fix must not break them.
        self.store.write_note("work/todo.txt", "ship it")
        self.assertEqual(self.store.read_note("work/todo.txt"), "ship it")

    def test_list_notes(self):
        self.store.write_note("a.txt", "1")
        self.store.write_note("work/b.txt", "2")
        self.assertEqual(self.store.list_notes(), ["a.txt", "work/b.txt"])

    def test_missing_note_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.store.read_note("nope.txt")


if __name__ == "__main__":
    unittest.main(verbosity=2)
