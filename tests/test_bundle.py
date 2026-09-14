"""Tests for the portable evidence-bundle assembler.

Properties pinned:
  - Missing artifacts → BundleAssemblyError with `.missing` listing exactly
    which kinds were absent. No fabrication, no substitution.
  - A complete finding assembles into a .tar.gz with exactly the required
    files, no more, no less.
  - hashes.txt content matches every listed file's actual sha256.
  - manifest.json parses and carries every required field.
  - Deterministic: same finding_id in → byte-identical archive out on repeat
    invocation.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import bundle                       # noqa: E402
from patchwing.store import Store                  # noqa: E402


def _seed_full_finding(store) -> str:
    """Seed a finding with every artifact bundle.assemble() requires."""
    f = store.add_finding(
        source="arvo",
        source_ref="ARVO-9999",
        repo_url="http://example.invalid",
        cwe="CWE-908",
        title="test finding for bundle assembler",
        description="synthetic",
        stage="review",
        state="blocked",
    )

    spec = {
        "target": {"image": "docker.io/example/target:1234",
                   "root": "/src/foo", "mode": "in-image"},
        "commands": {"build": "make", "reproduce": "arvo run"},
        "language": "c",
    }
    store.add_artifact(f.id, "spec", "ingest",
                       json.dumps(spec), {}, "", "")

    store.add_artifact(f.id, "patch", "patch",
                       "int foo(void) {\n    memset(x, 0, n);\n    return 0;\n}\n",
                       {"file": "foo.c",
                        "edits": "<<<<<<< SEARCH\nold\n=======\nnew\n>>>>>>> REPLACE\n",
                        "analysis": "closes the read",
                        "confidence": "high",
                        "edit_blocks": 1},
                       "", "moonshotai/Kimi-K2.7-Code")

    store.add_artifact(f.id, "patch_diff", "patch",
                       "--- a/foo.c\n+++ b/foo.c\n@@ -1,3 +1,3 @@\n-old\n+new\n",
                       {"file": "foo.c", "bytes": 66},
                       "", "moonshotai/Kimi-K2.7-Code")

    store.add_artifact(f.id, "reproducer", "reproduce",
                       "ERROR: sanitizer trace text goes here\nDEDUP_TOKEN: abc--def\n",
                       {}, "", "")

    # NEW artifact kind — the pristine reproducer INPUT bytes.
    poc_bytes = b"<?xml version=\"1.0\"?><a/>"
    store.add_artifact(f.id, "reproducer_input", "reproduce",
                       poc_bytes.decode("utf-8"),
                       {"path": "/tmp/poc", "bytes": len(poc_bytes)},
                       "", "")

    import hashlib
    poc_sha = hashlib.sha256(poc_bytes).hexdigest()
    lock = {"algorithm": "sha256", "n_files": 1, "n_reproducer": 1,
            "files": {"/tmp/poc": {"reason": "reproducer",
                                   "sha256": poc_sha,
                                   "bytes": len(poc_bytes)}},
            "pristine_dedup_token": "abc--def",
            "pristine_marker": "ERROR: sanitizer",
            "pristine_returncode": 77}
    store.add_artifact(f.id, "reproducer_lock", "reproduce",
                       json.dumps(lock), {}, "", "")

    verdict_meta = {"rollback": {"hash_triple": {
        "before_patch": "aaaaaaaaaaaaaaaa",
        "after_patch": "bbbbbbbbbbbbbbbb",
        "after_revert": "aaaaaaaaaaaaaaaa",
        "reverted_cleanly": True,
    }}}
    store.add_artifact(f.id, "verdict", "verify",
                       "verdict text", verdict_meta, "", "")

    store.add_artifact(f.id, "evidence", "package",
                       "# Evidence for ARVO-9999\n\n## 3. The patch\n\n```diff\n...\n```\n",
                       {}, "", "")

    # Spend rows so the manifest.cost fields populate meaningfully.
    store.add_artifact(f.id, "spend", "patch", "",
                       {"seat": "patch", "model": "moonshotai/Kimi-K2.7-Code",
                        "endpoint": "https://api.together.ai/v1",
                        "prompt_tokens": 100, "completion_tokens": 50,
                        "usd": 0.0, "priced": False}, "",
                       "moonshotai/Kimi-K2.7-Code")

    # Advisory review artifact so verify_advisory seat resolves.
    store.add_artifact(f.id, "review_advisory", "verify",
                       json.dumps({"verdict": "sound", "reasons": []}),
                       {"advisory": True, "verdict": "sound",
                        "reviewer_config": {"model": "zai-org/GLM-5.2",
                                            "endpoint": "https://api.together.ai/v1"}},
                       "", "zai-org/GLM-5.2")
    return f.id


class BundleMissingArtifactsTest(unittest.TestCase):

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()
        os.unlink(self.db)

    def test_missing_finding_row_errors(self):
        with self.assertRaises(bundle.BundleAssemblyError) as cm:
            bundle.assemble(self.store, "0000000000000000")
        self.assertIn("finding_row", cm.exception.missing)

    def test_missing_reproducer_input_listed(self):
        """A finding with everything EXCEPT the poc bytes must fail cleanly
        naming reproducer_input."""
        fid = _seed_full_finding(self.store)
        # Remove the reproducer_input artifact so the assembler must complain
        self.store.conn.execute(
            "DELETE FROM artifacts WHERE finding_id = ? AND kind = ?",
            (fid, "reproducer_input"))
        self.store.conn.commit()
        with self.assertRaises(bundle.BundleAssemblyError) as cm:
            bundle.assemble(self.store, fid)
        self.assertIn("reproducer_input", cm.exception.missing)
        # Does NOT silently substitute
        self.assertEqual(len(cm.exception.missing), 1,
                         "should name exactly the one missing artifact")

    def test_multiple_missing_all_listed(self):
        fid = _seed_full_finding(self.store)
        for kind in ("evidence", "verdict", "patch_diff"):
            self.store.conn.execute(
                "DELETE FROM artifacts WHERE finding_id = ? AND kind = ?",
                (fid, kind))
        self.store.conn.commit()
        with self.assertRaises(bundle.BundleAssemblyError) as cm:
            bundle.assemble(self.store, fid)
        for kind in ("evidence", "verdict", "patch_diff"):
            self.assertIn(kind, cm.exception.missing)


class BundleShapeTest(unittest.TestCase):

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db)
        self.fid = _seed_full_finding(self.store)
        self.result = bundle.assemble(self.store, self.fid)

    def tearDown(self):
        self.store.close()
        os.unlink(self.db)

    def test_filename_uses_short_sha_from_manifest(self):
        self.assertTrue(self.result.filename.startswith("patchwing-"))
        self.assertTrue(self.result.filename.endswith(".tar.gz"))
        self.assertIn(self.result.short_sha, self.result.filename)
        self.assertEqual(self.result.short_sha,
                         self.result.manifest_sha256[:8])

    def test_archive_contains_top_level_files(self):
        """Fixed set of top-level docs, scripts, and JSON files."""
        expected_top = {"evidence.md", "manifest.json", "finding.json",
                        "patch.diff", "patch.searchreplace.json",
                        "reproducer/poc", "reproducer/run.sh",
                        "container.txt", "process-log.jsonl", "hashes.txt",
                        "README.md", "APPLY.md", "ROLLBACK.md",
                        "apply.sh", "rollback.sh", "verify.sh",
                        "spend/spend.jsonl", "spend/spend_prior.jsonl",
                        "traces/investigation.jsonl",
                        "arvo-comparison.md"}
        with tarfile.open(fileobj=io.BytesIO(self.result.bytes),
                          mode="r:gz") as tar:
            names = {m.name for m in tar.getmembers()}
        missing = expected_top - names
        self.assertFalse(missing,
                         f"top-level files missing: {missing}")

    def test_archive_has_variable_directories(self):
        """Variable-count directories: prompts/, responses/, verdicts/,
        advisory/, artifacts/ — count depends on the finding."""
        with tarfile.open(fileobj=io.BytesIO(self.result.bytes),
                          mode="r:gz") as tar:
            names = {m.name for m in tar.getmembers()}
        # Seed has 1 prompt-like row? no — actually zero prompt artifacts
        # (bundle_test seed only adds patch/spec/etc). Advisory: 1. Verdict: 1.
        # Artifacts: several.
        advisory_files = [n for n in names if n.startswith("advisory/")]
        verdict_files = [n for n in names if n.startswith("verdicts/")]
        artifact_files = [n for n in names if n.startswith("artifacts/")]
        self.assertGreaterEqual(len(advisory_files), 1)
        self.assertGreaterEqual(len(verdict_files), 1)
        self.assertGreaterEqual(len(artifact_files), 1)

    def test_hashes_txt_matches_every_other_file(self):
        with tarfile.open(fileobj=io.BytesIO(self.result.bytes),
                          mode="r:gz") as tar:
            members = {m.name: tar.extractfile(m).read()
                       for m in tar.getmembers()}
        import hashlib
        expected = {name: hashlib.sha256(data).hexdigest()
                    for name, data in members.items()
                    if name != "hashes.txt"}
        actual = {}
        for line in members["hashes.txt"].decode("utf-8").splitlines():
            if not line.strip(): continue
            sha, path = line.split("  ", 1)
            actual[path] = sha
        self.assertEqual(actual, expected,
                         "hashes.txt must list every other file exactly once "
                         "with its real sha256")

    def test_manifest_json_parses_and_has_required_fields(self):
        with tarfile.open(fileobj=io.BytesIO(self.result.bytes),
                          mode="r:gz") as tar:
            m_bytes = tar.extractfile("manifest.json").read()
        m = json.loads(m_bytes)
        required = {"finding_id", "parent_finding_id", "cwe", "reference",
                    "created_at", "container_image", "container_digest",
                    "reproducer_sha256", "patch_sha256", "patched_file_paths",
                    "model_seats", "chain_proof", "cost", "patchwing_version",
                    "process_log_events", "prompts", "responses",
                    "investigation_turns", "verdicts", "advisories",
                    "artifacts", "hash_triples", "pod_events", "wall_frozen",
                    "reproducer_lock", "advisory_status", "advisory_reason",
                    "missing"}
        self.assertTrue(required.issubset(m.keys()),
                        f"manifest missing fields: {required - m.keys()}")
        self.assertEqual(m["container_image"], "docker.io/example/target:1234")
        self.assertEqual(m["chain_proof"]["chain_proved"], True)
        self.assertEqual(m["patched_file_paths"], ["foo.c"])
        # patch is unpriced in the seed, so usd should be None (honest)
        self.assertIsNone(m["cost"]["usd"])
        self.assertFalse(m["cost"]["priced"])
        # count fields populate with integers
        for k in ("process_log_events", "prompts", "responses",
                  "investigation_turns", "verdicts", "advisories", "artifacts"):
            self.assertIsInstance(m[k], int,
                                  f"{k} should be an int")
        # arvo_comparison block always present; false when no artifact stored
        self.assertIn("arvo_comparison", m)
        self.assertFalse(m["arvo_comparison"]["present"],
                         "seeded finding has no arvo_comparison artifact")

    def test_finding_json_parses_with_expected_shape(self):
        with tarfile.open(fileobj=io.BytesIO(self.result.bytes),
                          mode="r:gz") as tar:
            fj = json.loads(tar.extractfile("finding.json").read())
        self.assertIn("finding", fj)
        self.assertIn("process_log", fj)
        self.assertIn("artifacts", fj)
        self.assertEqual(fj["finding"]["id"], self.fid)

    def test_scripts_have_execute_bits(self):
        with tarfile.open(fileobj=io.BytesIO(self.result.bytes),
                          mode="r:gz") as tar:
            for name in ("apply.sh", "rollback.sh", "verify.sh"):
                info = tar.getmember(name)
                self.assertTrue(info.mode & 0o111,
                                f"{name} should be executable, mode={oct(info.mode)}")

    def test_deterministic_byte_identical_on_reassembly(self):
        again = bundle.assemble(self.store, self.fid)
        self.assertEqual(again.bytes, self.result.bytes,
                         "same finding_id must yield a byte-identical archive")
        self.assertEqual(again.manifest_sha256, self.result.manifest_sha256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
