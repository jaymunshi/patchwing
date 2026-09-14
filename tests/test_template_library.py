"""Template library API — templates_list, template_get, template_verify
+ the verify_template helper. Uses fresh temp Store + mocked sandbox so
no real podman calls happen."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from dataclasses import dataclass
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import sandbox as sandbox_mod                  # noqa: E402
from patchwing import template_builder as tb                  # noqa: E402
from patchwing import templates as tpl_mod                    # noqa: E402
from patchwing.store import Store                             # noqa: E402


@dataclass
class _Run:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    duration_s: float = 0.01
    timed_out: bool = False


class FakeSandbox:
    backend = "podman"
    cid = "verifycid"

    def __init__(self, run_map=None):
        self.run_map = run_map or {}
        self.prepared = False
        self.cleaned = False

    def prepare(self, src_dir=""):
        self.prepared = True

    def run(self, cmd, timeout_s=60):
        for k, v in self.run_map.items():
            if k in cmd:
                return v
        return _Run(stdout="")

    def cleanup(self):
        self.cleaned = True


def _mk_store():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Store(tmp.name), tmp.name


def _rm(p):
    try: os.unlink(p)
    except OSError: pass


def _seed(store, name="tomcat-jdk8", ok=True):
    return store.add_template(
        name=name,
        description=f"{name} desc",
        base_image="ubuntu:22.04",
        image_tag=tpl_mod.image_tag_for(name),
        recipe_json=json.dumps([{"tool": "install_package",
                                 "args": {"name": "curl", "timeout_s": 600}}]),
        recipe_turn_count=1,
        verification_cmd="curl -sSi http://127.0.0.1:8080/",
        verification_expect=r"HTTP/1\.1 200",
        builder_version=tpl_mod.BUILDER_VERSION_CURRENT,
        image_size_bytes=100_000_000,
        image_digest="sha256:" + ("a" if ok else "b") * 64,
        cve_class_hint="java-servlet-web-rce")


# --- verify_template helper ----------------------------------------------

class VerifyTemplateHelperTest(unittest.TestCase):

    def test_success_updates_row(self):
        store, path = _mk_store()
        try:
            t = _seed(store)
            fake = FakeSandbox({"curl": _Run(
                stdout="HTTP/1.1 200 OK\nServer: something\n")})
            with mock.patch.object(sandbox_mod, "make",
                                   return_value=fake):
                result = tb.verify_template(
                    store=store, sandbox_config=None, template=t)
            self.assertTrue(result["ok"])
            self.assertEqual("", result["error"])
            # Row persisted
            fresh = store.get_template(t.id)
            self.assertEqual(1, fresh.last_verified_ok)
            self.assertIsNotNone(fresh.last_verified_at)
            # Sandbox lifecycle
            self.assertTrue(fake.prepared)
            self.assertTrue(fake.cleaned)
        finally:
            store.close(); _rm(path)

    def test_regex_mismatch_persists_failure(self):
        store, path = _mk_store()
        try:
            t = _seed(store)
            fake = FakeSandbox({"curl": _Run(
                stdout="HTTP/1.1 500 Internal Server Error\n")})
            with mock.patch.object(sandbox_mod, "make",
                                   return_value=fake):
                result = tb.verify_template(
                    store=store, sandbox_config=None, template=t)
            self.assertFalse(result["ok"])
            self.assertIn("did not match", result["error"])
            fresh = store.get_template(t.id)
            self.assertEqual(0, fresh.last_verified_ok)
            self.assertIn("did not match", fresh.last_verified_note)

        finally:
            store.close(); _rm(path)

    def test_pod_prep_failure_persists_as_verify_failure(self):
        store, path = _mk_store()
        try:
            t = _seed(store)
            fake = FakeSandbox()
            fake.prepare = mock.Mock(
                side_effect=sandbox_mod.SandboxError("no such image"))
            with mock.patch.object(sandbox_mod, "make",
                                   return_value=fake):
                result = tb.verify_template(
                    store=store, sandbox_config=None, template=t)
            self.assertFalse(result["ok"])
            self.assertIn("pod prep failed", result["error"])
            fresh = store.get_template(t.id)
            self.assertEqual(0, fresh.last_verified_ok)
        finally:
            store.close(); _rm(path)

    def test_cleanup_still_runs_on_failure(self):
        store, path = _mk_store()
        try:
            t = _seed(store)
            fake = FakeSandbox()
            fake.run = mock.Mock(
                side_effect=sandbox_mod.SandboxError("boom"))
            with mock.patch.object(sandbox_mod, "make",
                                   return_value=fake):
                tb.verify_template(store=store, sandbox_config=None,
                                   template=t)
            self.assertTrue(fake.cleaned)
        finally:
            store.close(); _rm(path)


# --- App.templates_list / template_get / template_verify ----------------
# These test the server-side App methods directly (no HTTP layer) using
# a real Store + mocked sandbox for verify.

class _FakeConfig:
    class _Sbx:
        backend = "podman"; image = ""; network = "none"
        cpus = 2.0; memory = "4g"; timeout_s = 1800
    sandbox = _Sbx()


class AppTemplateEndpointsTest(unittest.TestCase):

    def _mk_app(self):
        # server.App wants a db path + config; build against the temp DB
        from patchwing.server import App
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        app = App(db=tmp.name, config=_FakeConfig())
        return app, tmp.name

    def test_templates_list_omits_recipe_body(self):
        app, path = self._mk_app()
        try:
            s = app.store()
            try: _seed(s, name="tomcat-jdk8"); _seed(s, name="apache-httpd-24")
            finally: s.close()
            resp = app.templates_list()
            names = [t["name"] for t in resp["templates"]]
            self.assertEqual(2, len(names))
            # Order: newest first
            self.assertEqual(["apache-httpd-24", "tomcat-jdk8"], names)
            # recipe_json is stripped from list view
            for t in resp["templates"]:
                self.assertNotIn("recipe_json", t)
        finally:
            app.close_pool() if hasattr(app, "close_pool") else None
            _rm(path)

    def test_template_get_by_name_returns_parsed_recipe(self):
        app, path = self._mk_app()
        try:
            s = app.store()
            try: _seed(s, name="tomcat-jdk8")
            finally: s.close()
            resp = app.template_get("tomcat-jdk8")
            self.assertTrue(resp["ok"])
            self.assertEqual("tomcat-jdk8", resp["template"]["name"])
            self.assertEqual(1, len(resp["template"]["recipe"]))
            self.assertEqual("install_package",
                             resp["template"]["recipe"][0]["tool"])
        finally:
            _rm(path)

    def test_template_get_by_id_works_too(self):
        app, path = self._mk_app()
        try:
            s = app.store()
            try: t = _seed(s, name="nodejs-18")
            finally: s.close()
            resp = app.template_get(t.id)
            self.assertTrue(resp["ok"])
            self.assertEqual("nodejs-18", resp["template"]["name"])
        finally:
            _rm(path)

    def test_template_get_missing_returns_error(self):
        app, path = self._mk_app()
        try:
            resp = app.template_get("nope")
            self.assertFalse(resp["ok"])
            self.assertIn("not found", resp["error"])
        finally:
            _rm(path)

    def test_template_verify_success_returns_updated_state(self):
        app, path = self._mk_app()
        try:
            s = app.store()
            try: t = _seed(s, name="tomcat-jdk8")
            finally: s.close()

            fake = FakeSandbox({"curl": _Run(
                stdout="HTTP/1.1 200 OK\n")})
            with mock.patch.object(sandbox_mod, "make",
                                   return_value=fake):
                resp = app.template_verify(t.id)
            self.assertTrue(resp["ok"])
            self.assertTrue(resp["verified_ok"])
            self.assertEqual(1, resp["last_verified_ok"])
            self.assertIsNotNone(resp["last_verified_at"])
        finally:
            _rm(path)

    def test_template_verify_failure_persists_and_reports(self):
        app, path = self._mk_app()
        try:
            s = app.store()
            try: t = _seed(s, name="tomcat-jdk8")
            finally: s.close()

            fake = FakeSandbox({"curl": _Run(
                stdout="HTTP/1.1 500 Internal Server Error\n")})
            with mock.patch.object(sandbox_mod, "make",
                                   return_value=fake):
                resp = app.template_verify(t.id)
            self.assertTrue(resp["ok"])       # endpoint call succeeded
            self.assertFalse(resp["verified_ok"])   # but verify failed
            self.assertEqual(0, resp["last_verified_ok"])
            self.assertIn("did not match", resp["error"])
        finally:
            _rm(path)

    def test_template_verify_missing_returns_error(self):
        app, path = self._mk_app()
        try:
            resp = app.template_verify("does-not-exist")
            self.assertFalse(resp["ok"])
            self.assertIn("not found", resp["error"])
        finally:
            _rm(path)


# --- draft_spec_save + preferred_template existence check (Step 5) ------

class DraftSpecSavePreferredTemplateTest(unittest.TestCase):
    """The server-side draft-save endpoint calls
    validate_preferred_template_exists(). Confirm that a preferred_template
    naming a non-existent row is REJECTED at save, not silently persisted."""

    def _mk_app(self):
        from patchwing.server import App
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        app = App(db=tmp.name, config=_FakeConfig())
        return app, tmp.name

    def _seed_localize_finding(self, app, fid="TEST-STEP5"):
        s = app.store()
        try:
            import time
            s.conn.execute(
                "INSERT INTO findings(id, source, source_ref, repo_url, "
                "repo_ref, base_commit, cwe, title, description, stage, "
                "state, attempts, error, created_at, updated_at, owner, "
                "container_id, parent_finding_id) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fid, "advisory", "CVE-STEP5", "", "", "", "",
                 "test", "test", "localize", "pending", 0, "",
                 time.time(), time.time(), "", "", ""))
            s.conn.commit()
        finally:
            s.close()

    def _base_payload(self, extra=None):
        p = {
            "endpoint_path_norm": "/eval", "method": "GET",
            "expected_status_red": 200,
            "evidence_rules": [
                {"name": "reflection", "kind": "response_body_regex",
                 "pattern": r"uid=\d+"}]}
        if extra: p.update(extra)
        return p

    def test_save_with_valid_preferred_template_ok(self):
        app, path = self._mk_app()
        try:
            self._seed_localize_finding(app)
            s = app.store()
            try: _seed(s, name="tomcat-jdk8")
            finally: s.close()
            resp = app.draft_spec_save(
                "TEST-STEP5",
                self._base_payload({"preferred_template": "tomcat-jdk8"}))
            self.assertTrue(resp["ok"], msg=str(resp))
        finally:
            _rm(path)

    def test_save_with_unknown_preferred_template_rejected(self):
        app, path = self._mk_app()
        try:
            self._seed_localize_finding(app)
            resp = app.draft_spec_save(
                "TEST-STEP5",
                self._base_payload({"preferred_template": "nope-doesnt-exist"}))
            self.assertFalse(resp["ok"])
            self.assertIn("nope-doesnt-exist", resp["error"])
        finally:
            _rm(path)

    def test_save_without_preferred_template_still_works(self):
        """Backward-compat inside the endpoint: an operator who doesn't
        pick a template must still be able to save a draft."""
        app, path = self._mk_app()
        try:
            self._seed_localize_finding(app)
            resp = app.draft_spec_save("TEST-STEP5", self._base_payload())
            self.assertTrue(resp["ok"], msg=str(resp))
            # No template referenced ≠ store touched — no rows created
            s = app.store()
            try:
                self.assertEqual([], s.list_templates())
            finally:
                s.close()
        finally:
            _rm(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
