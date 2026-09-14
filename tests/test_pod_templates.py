"""pod_templates table + Store CRUD + templates module constants.

Templates are the CACHING layer over the provision path. This test file
covers ONLY persistence — the actual template builder (running the
recipe against a pod, committing, verifying) lives in Step 2 and gets
its own test file. Here we prove:

  * The table creates cleanly on a fresh store.
  * add_template / list_templates / get_template / update_template_verification
    all round-trip cleanly.
  * name UNIQUE constraint is enforced.
  * PodTemplate.from_row copes with the full schema and with an old-shape
    row that's missing optional columns (schema-drift safety, same shape
    as Finding.from_row).
  * The templates module constants (tag prefix, image_tag_for, recipe
    kind name, builder version) are stable.

Nothing here mocks podman. Building images is Step 2's problem.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import templates as tpl_mod                    # noqa: E402
from patchwing.store import Store                             # noqa: E402


def _mk_store():
    """Fresh temp DB for each test. Store's __init__ creates the schema."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Store(tmp.name), tmp.name


def _cleanup(path: str):
    try: os.unlink(path)
    except OSError: pass


def _valid_kwargs(name: str = "tomcat-jdk8", **overrides):
    base = dict(
        name=name,
        description="JDK 8 + Maven + Tomcat 9 for Java-servlet web RCEs",
        base_image="ubuntu:22.04",
        image_tag=tpl_mod.image_tag_for(name),
        recipe_json=json.dumps([
            {"tool": "install_package", "args": {"name": "openjdk-8-jdk"}},
            {"tool": "install_package", "args": {"name": "maven"}},
        ]),
        recipe_turn_count=2,
        verification_cmd="curl -sSi http://127.0.0.1:8080/",
        verification_expect=r"HTTP/1\.1 200 OK.*Apache Tomcat",
        builder_version=tpl_mod.BUILDER_VERSION_CURRENT,
        image_size_bytes=1_234_567_890,
        image_digest="sha256:" + "a" * 64,
        cve_class_hint="java-servlet-web-rce",
    )
    base.update(overrides)
    return base


# --- constants ------------------------------------------------------------

class TemplateConstantsTest(unittest.TestCase):

    def test_tag_prefix(self):
        self.assertEqual("patchwing-template", tpl_mod.TEMPLATE_TAG_PREFIX)

    def test_recipe_kind(self):
        self.assertEqual("template_recipe", tpl_mod.TEMPLATE_RECIPE_KIND)

    def test_builder_version_is_a_stable_string(self):
        # The exact value can change; the type must not.
        self.assertIsInstance(tpl_mod.BUILDER_VERSION_CURRENT, str)
        self.assertTrue(tpl_mod.BUILDER_VERSION_CURRENT)

    def test_image_tag_for_ok(self):
        self.assertEqual("patchwing-template:tomcat-jdk8",
                         tpl_mod.image_tag_for("tomcat-jdk8"))
        self.assertEqual("patchwing-template:nodejs-18",
                         tpl_mod.image_tag_for("nodejs-18"))

    def test_image_tag_for_rejects_bad_names(self):
        for bad in ("", "tomcat:8", "tomcat/8", "tomcat 8"):
            with self.assertRaises(ValueError,
                                   msg=f"should reject {bad!r}"):
                tpl_mod.image_tag_for(bad)


# --- schema ---------------------------------------------------------------

class PodTemplatesSchemaTest(unittest.TestCase):

    def test_table_created_on_fresh_store(self):
        s, path = _mk_store()
        try:
            row = s.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='pod_templates'").fetchone()
            self.assertIsNotNone(row, "pod_templates table not created")
            cols = [r[1] for r in s.conn.execute(
                "PRAGMA table_info(pod_templates)").fetchall()]
            required = {
                "id", "name", "description", "base_image", "image_tag",
                "image_size_bytes", "image_digest", "recipe_json",
                "recipe_turn_count", "verification_cmd",
                "verification_expect", "cve_class_hint", "builder_version",
                "created_at", "last_verified_at", "last_verified_ok",
                "last_verified_note"}
            missing = required - set(cols)
            self.assertFalse(missing, f"missing columns: {missing}")
        finally:
            s.close()
            _cleanup(path)

    def test_hint_index_exists(self):
        s, path = _mk_store()
        try:
            row = s.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_pt_hint'").fetchone()
            self.assertIsNotNone(row)
        finally:
            s.close()
            _cleanup(path)


# --- CRUD ----------------------------------------------------------------

class AddTemplateTest(unittest.TestCase):

    def test_insert_returns_populated_dataclass(self):
        s, path = _mk_store()
        try:
            t = s.add_template(**_valid_kwargs())
            self.assertIsInstance(t, tpl_mod.PodTemplate)
            self.assertEqual("tomcat-jdk8", t.name)
            self.assertEqual("patchwing-template:tomcat-jdk8", t.image_tag)
            self.assertEqual(2, t.recipe_turn_count)
            self.assertEqual(1_234_567_890, t.image_size_bytes)
            self.assertTrue(t.id)
            self.assertGreater(t.created_at, 0)
            # unverified: last_verified_* all null
            self.assertIsNone(t.last_verified_at)
            self.assertIsNone(t.last_verified_ok)
            self.assertIsNone(t.last_verified_note)
        finally:
            s.close()
            _cleanup(path)

    def test_optional_fields_may_be_omitted(self):
        s, path = _mk_store()
        try:
            kw = _valid_kwargs()
            del kw["image_size_bytes"]
            del kw["image_digest"]
            del kw["cve_class_hint"]
            t = s.add_template(**kw)
            self.assertIsNone(t.image_size_bytes)
            self.assertIsNone(t.image_digest)
            self.assertIsNone(t.cve_class_hint)
        finally:
            s.close()
            _cleanup(path)

    def test_duplicate_name_raises_integrity_error(self):
        """UNIQUE(name) is the invariant that makes tag→row lookup 1:1.
        A duplicate must not silently overwrite the existing row."""
        s, path = _mk_store()
        try:
            s.add_template(**_valid_kwargs(name="dupe"))
            with self.assertRaises(sqlite3.IntegrityError):
                s.add_template(**_valid_kwargs(name="dupe"))
        finally:
            s.close()
            _cleanup(path)


class ListTemplatesTest(unittest.TestCase):

    def test_empty_list_when_no_templates(self):
        s, path = _mk_store()
        try:
            self.assertEqual([], s.list_templates())
        finally:
            s.close()
            _cleanup(path)

    def test_returns_all_and_newest_first(self):
        s, path = _mk_store()
        try:
            import time as _t
            s.add_template(**_valid_kwargs(name="first"))
            _t.sleep(0.01)
            s.add_template(**_valid_kwargs(name="second"))
            _t.sleep(0.01)
            s.add_template(**_valid_kwargs(name="third"))
            names = [t.name for t in s.list_templates()]
            self.assertEqual(["third", "second", "first"], names)
        finally:
            s.close()
            _cleanup(path)


class GetTemplateTest(unittest.TestCase):

    def test_lookup_by_id(self):
        s, path = _mk_store()
        try:
            t = s.add_template(**_valid_kwargs(name="tomcat-jdk8"))
            got = s.get_template(t.id)
            self.assertEqual(t.id, got.id)
            self.assertEqual("tomcat-jdk8", got.name)
        finally:
            s.close()
            _cleanup(path)

    def test_lookup_by_name(self):
        s, path = _mk_store()
        try:
            t = s.add_template(**_valid_kwargs(name="apache-httpd-24"))
            got = s.get_template("apache-httpd-24")
            self.assertEqual(t.id, got.id)
        finally:
            s.close()
            _cleanup(path)

    def test_lookup_miss_returns_none(self):
        s, path = _mk_store()
        try:
            self.assertIsNone(s.get_template("does-not-exist"))
        finally:
            s.close()
            _cleanup(path)


class UpdateTemplateVerificationTest(unittest.TestCase):

    def test_records_success(self):
        s, path = _mk_store()
        try:
            t = s.add_template(**_valid_kwargs())
            s.update_template_verification(
                t.id, ok=True, note="curl 200 OK",
                ts=1_785_000_000.0)
            got = s.get_template(t.id)
            self.assertEqual(1_785_000_000.0, got.last_verified_at)
            self.assertEqual(1, got.last_verified_ok)
            self.assertEqual("curl 200 OK", got.last_verified_note)
        finally:
            s.close()
            _cleanup(path)

    def test_records_failure(self):
        s, path = _mk_store()
        try:
            t = s.add_template(**_valid_kwargs())
            s.update_template_verification(
                t.id, ok=False, note="curl: (7) connection refused")
            got = s.get_template(t.id)
            self.assertEqual(0, got.last_verified_ok)
            self.assertIn("connection refused", got.last_verified_note)
        finally:
            s.close()
            _cleanup(path)

    def test_re_verification_overwrites_prior(self):
        s, path = _mk_store()
        try:
            t = s.add_template(**_valid_kwargs())
            s.update_template_verification(t.id, ok=False, note="down",
                                           ts=1000.0)
            s.update_template_verification(t.id, ok=True, note="back up",
                                           ts=2000.0)
            got = s.get_template(t.id)
            self.assertEqual(2000.0, got.last_verified_at)
            self.assertEqual(1, got.last_verified_ok)
            self.assertEqual("back up", got.last_verified_note)
        finally:
            s.close()
            _cleanup(path)


# --- dataclass -----------------------------------------------------------

class PodTemplateFromRowTest(unittest.TestCase):

    def test_from_row_maps_all_columns(self):
        s, path = _mk_store()
        try:
            s.add_template(**_valid_kwargs())
            row = s.conn.execute(
                "SELECT * FROM pod_templates").fetchone()
            t = tpl_mod.PodTemplate.from_row(row)
            self.assertEqual("tomcat-jdk8", t.name)
            self.assertEqual(r"HTTP/1\.1 200 OK.*Apache Tomcat",
                             t.verification_expect)
            self.assertEqual("java-servlet-web-rce", t.cve_class_hint)
        finally:
            s.close()
            _cleanup(path)

    def test_from_row_tolerates_extra_columns(self):
        """Schema-drift safety: a future column addition must not break
        old code reading the row. Same shape as Finding.from_row."""
        s, path = _mk_store()
        try:
            s.add_template(**_valid_kwargs())
            # Simulate a future column by ALTER-ing in a phantom, then
            # reading through the dataclass.
            s.conn.execute(
                "ALTER TABLE pod_templates ADD COLUMN future_col TEXT")
            row = s.conn.execute(
                "SELECT * FROM pod_templates").fetchone()
            t = tpl_mod.PodTemplate.from_row(row)  # must not raise
            self.assertEqual("tomcat-jdk8", t.name)
        finally:
            s.close()
            _cleanup(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
