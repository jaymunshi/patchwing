"""Tests for the reproducer wall.

The wall's claim is that a PatchWing verdict cannot be obtained by weakening the
test that proves the bug. These tests exercise that claim directly, including the
attack it exists to stop: a fix-writer that edits the reproducer instead of the
vulnerable source.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import wall  # noqa: E402


def _write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class WallTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pw-wall-")
        _write(self.root, "reproducer.py", "raise SystemExit(1)  # bug present\n")
        _write(self.root, "notes/store.py", "def read(p):\n    return open(p).read()\n")
        _write(self.root, "tests/test_store.py", "def test_ok():\n    assert True\n")
        # DECLARED, never inferred. Inference is what let the wall be silently
        # empty on a target whose reproduce command contains no path.
        self.spec = {"commands": {"reproduce": "python reproducer.py",
                                  "test": "python -m pytest"},
                     "reproducer": {"files": ["reproducer.py"]}}

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    # -- identification ----------------------------------------------------

    def test_uses_declared_reproducer(self):
        self.assertEqual(wall.reproducer_files(self.spec, self.root),
                         ["reproducer.py"])

    def test_never_infers_from_the_command(self):
        """A reproduce command with no path must yield NOTHING, not a guess.

        `arvo run` has no path in it. The old inference returned an empty set and
        the wall reported success while protecting nothing.
        """
        spec = {"commands": {"reproduce": "arvo run"}}
        self.assertEqual(wall.reproducer_files(spec, self.root), [])

    def test_declaration_is_the_only_source(self):
        spec = dict(self.spec, reproducer={"files": ["notes/store.py"]})
        self.assertEqual(wall.reproducer_files(spec, self.root), ["notes/store.py"])

    def test_declared_empty_suite_is_not_scanned(self):
        """`files = []` states this corpus has no suite; absent means scan.

        On ARVO the scan would sweep 1483 SOURCE files into the frozen set and
        make the very file the fix-writer must edit immutable.
        """
        spec = dict(self.spec, suite={"files": []})
        prot = wall.protected_files(spec, self.root)
        self.assertEqual(set(prot.values()), {"reproducer"})
        self.assertNotIn("tests/test_store.py", prot)

    def test_protects_reproducer_and_suite_but_not_source(self):
        prot = wall.protected_files(self.spec, self.root)
        self.assertEqual(prot.get("reproducer.py"), "reproducer")
        self.assertEqual(prot.get("tests/test_store.py"), "suite")
        self.assertNotIn("notes/store.py", prot,
                         "vulnerable source must remain patchable")

    # -- the guarantee -----------------------------------------------------

    def test_unmodified_tree_passes(self):
        m = wall.freeze(self.spec, self.root)
        self.assertEqual(wall.check(self.root, m), [])

    def test_patching_the_source_does_not_trip_the_wall(self):
        m = wall.freeze(self.spec, self.root)
        _write(self.root, "notes/store.py", "def read(p):\n    return 'safe'\n")
        self.assertEqual(wall.check(self.root, m), [],
                         "a legitimate fix must not be flagged")

    def test_rewriting_the_reproducer_is_caught(self):
        """The attack: neuter the reproducer so any patch looks correct."""
        m = wall.freeze(self.spec, self.root)
        _write(self.root, "reproducer.py", "raise SystemExit(0)  # 'fixed'\n")
        v = wall.check(self.root, m)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["file"], "reproducer.py")
        self.assertEqual(v[0]["reason"], "reproducer")
        self.assertEqual(v[0]["problem"], "modified")

    def test_weakening_the_suite_is_caught(self):
        m = wall.freeze(self.spec, self.root)
        _write(self.root, "tests/test_store.py", "def test_ok():\n    pass\n")
        v = wall.check(self.root, m)
        self.assertEqual([x["reason"] for x in v], ["suite"])

    def test_deleting_the_reproducer_is_caught(self):
        m = wall.freeze(self.spec, self.root)
        os.remove(os.path.join(self.root, "reproducer.py"))
        v = wall.check(self.root, m)
        self.assertEqual(v[0]["problem"], "deleted")

    def test_whitespace_only_edit_is_caught(self):
        """Hashes are byte-exact; a 'harmless' reformat still voids the run."""
        m = wall.freeze(self.spec, self.root)
        _write(self.root, "reproducer.py", "raise SystemExit(1)  # bug present\n\n")
        self.assertEqual(len(wall.check(self.root, m)), 1)

    # -- patch-stage gate --------------------------------------------------

    def test_is_protected_gates_the_patch_target(self):
        m = wall.freeze(self.spec, self.root)
        self.assertEqual(wall.is_protected("reproducer.py", m), "reproducer")
        self.assertEqual(wall.is_protected("tests/test_store.py", m), "suite")
        self.assertIsNone(wall.is_protected("notes/store.py", m))

    def test_harden_removes_write_bits(self):
        m = wall.freeze(self.spec, self.root)
        n = wall.harden(self.root, m)
        self.assertGreater(n, 0)
        mode = os.stat(os.path.join(self.root, "reproducer.py")).st_mode
        self.assertFalse(mode & 0o222, "write bits should be cleared")

    def test_manifest_records_reason_and_hash(self):
        m = wall.freeze(self.spec, self.root)
        self.assertEqual(m["algorithm"], "sha256")
        self.assertEqual(m["n_reproducer"], 1)
        ent = m["files"]["reproducer.py"]
        self.assertEqual(len(ent["sha256"]), 64)
        self.assertEqual(ent["reason"], "reproducer")




class HardAbortTest(unittest.TestCase):
    """An empty reproducer set must ABORT, never proceed.

    This is the bug that shipped: the wall inferred zero reproducer files from
    `arvo run`, froze 1483 unrelated files, and reported success.
    """

    class FakeSb:
        def __init__(self, files):
            self.files = files

        def run(self, cmd):
            import re as _re
            m = _re.search(r"(?:sha256sum|md5sum) (\S+)", cmd)
            path = m.group(1) if m else ""
            class R:
                pass
            r = R()
            r.stdout = (f"{self.files[path]}\n262\n" if path in self.files else "")
            r.returncode = 0
            return r

    def test_aborts_when_no_reproducer_declared(self):
        sb = self.FakeSb({})
        with self.assertRaises(wall.WallError) as cm:
            wall.freeze_in_sandbox(sb, {"commands": {"reproduce": "arvo run"}})
        self.assertIn("no reproducer files declared", str(cm.exception))

    def test_aborts_when_declared_file_absent_in_image(self):
        sb = self.FakeSb({})
        with self.assertRaises(wall.WallError) as cm:
            wall.freeze_in_sandbox(sb, {"reproducer": {"files": ["/tmp/poc"]}})
        self.assertIn("does not exist in the image", str(cm.exception))

    def test_freezes_an_absolute_path_outside_root(self):
        sb = self.FakeSb({"/tmp/poc": "5c8b4544f00c5b5c5638ccd79b1bdfcbde"
                              "37d54f65c6ce547be8d60bd4169db3"})
        m = wall.freeze_in_sandbox(sb, {"reproducer": {"files": ["/tmp/poc"]},
                                        "suite": {"files": []}})
        self.assertEqual(m["n_reproducer"], 1)
        self.assertTrue(m["suite_declared_empty"])
        self.assertEqual(m["files"]["/tmp/poc"]["sha256"],
                         "5c8b4544f00c5b5c5638ccd79b1bdfcbde"
                         "37d54f65c6ce547be8d60bd4169db3")
        self.assertEqual(m["algorithm"], "sha256")

    def test_patch_target_inside_frozen_set_is_rejected(self):
        m = {"files": {"/tmp/poc": {"reason": "reproducer"},
                       "SAX2.c": {"reason": "suite"}}}
        wall.assert_patchable("parserInternals.c", m)      # fine
        with self.assertRaises(wall.WallError) as cm:
            wall.assert_patchable("SAX2.c", m)
        self.assertIn("disjoint", str(cm.exception))



class HashLabelTest(unittest.TestCase):
    """The named algorithm and the printed value must agree.

    A 32-hex md5 recorded under a "sha256" key makes an honest verifier compute
    sha256, mismatch, and conclude tampering — a false tamper signal inside the
    tamper-evidence artifact.
    """

    def test_wrong_length_hash_is_refused(self):
        sb = HardAbortTest.FakeSb({"/tmp/poc": "32bb851c178658b5763f21fc159aaede"})
        with self.assertRaises(wall.WallError) as cm:
            wall.freeze_in_sandbox(sb, {"reproducer": {"files": ["/tmp/poc"]}})
        self.assertIn("64-hex sha256", str(cm.exception))

if __name__ == "__main__":
    unittest.main(verbosity=2)
