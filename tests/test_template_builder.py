"""Template builder — recorder + build_template.

Podman/docker are external deps we don't have in the suite environment,
so this test file mocks:
  * `sandbox_mod.make` — returns a FakeSandbox that records prepare/
    run/cleanup calls
  * `subprocess.run` — for podman inspect + rmi
  * `provision_mod.commit_pod` — pass-through, so the code path runs but
    no real container commit happens

Every test uses a fresh temp SQLite Store — no shared state.

What we prove:
  * TemplateRecorder captures each of the four provision-tool calls
    exactly once and in order, and delegates to the real provision
    functions.
  * build_template's happy path: creates a build pod, runs recipe_fn,
    commits, inspects digest+size, verifies in a FRESH pod, persists.
  * Verification failure removes the image AND does not persist.
  * Recipe-fn raises → wrapped as BuildFailed with stage='recipe'.
  * Recipe-fn missing verification_cmd/expect → refused before commit.
  * Bad regex in verification_expect → refused before commit.
  * Duplicate name precheck refuses before touching podman.
  * Commit failure raises BuildFailed with stage='commit'.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import dataclass
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import provision as provision_mod              # noqa: E402
from patchwing import sandbox as sandbox_mod                  # noqa: E402
from patchwing import template_builder as tb                  # noqa: E402
from patchwing import templates as tpl_mod                    # noqa: E402
from patchwing.store import Store                             # noqa: E402


# --- fixtures ------------------------------------------------------------

@dataclass
class _Run:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    duration_s: float = 0.01
    timed_out: bool = False


class FakeSandbox:
    """Passable to provision tools and to template_builder. Records
    every method call so tests can assert on the interaction sequence."""

    backend = "podman"
    cid = "fakecid1234"

    def __init__(self, run_map=None):
        self.run_map = run_map or {}
        self.runs: list[str] = []
        self.writes: list[tuple[str, str]] = []
        self.prepared = False
        self.cleaned = False

    def prepare(self, src_dir: str = ""):
        self.prepared = True

    def run(self, cmd, timeout_s=60):
        self.runs.append(cmd)
        for key, val in self.run_map.items():
            if key in cmd:
                return val
        return _Run(stdout="", returncode=0)

    def write(self, path, content):
        self.writes.append((path, content))

    def read(self, path):
        return ""

    def cleanup(self):
        self.cleaned = True

    def __enter__(self): return self
    def __exit__(self, *exc): self.cleanup(); return False


def _mk_store():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Store(tmp.name), tmp.name


def _rm(p):
    try: os.unlink(p)
    except OSError: pass


class _FakeSbxCfg:
    """Placeholder — passed into sandbox_mod.make (mocked in tests)."""
    backend = "podman"
    image = ""
    network = "none"
    cpus = 2.0
    memory = "4g"
    timeout_s = 1800


def _completed(stdout="", stderr="", returncode=0):
    """CompletedProcess-shaped stand-in for subprocess.run mock returns."""
    p = mock.Mock()
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = returncode
    return p


# --- TemplateRecorder ----------------------------------------------------

class TemplateRecorderTest(unittest.TestCase):

    def test_records_exec_in_pod(self):
        sb = FakeSandbox({"echo hi": _Run(stdout="hi\n", returncode=0)})
        rec = tb.TemplateRecorder(sb)
        out = rec.exec_in_pod("echo hi", timeout_s=30)
        self.assertIn("hi", out)
        self.assertEqual(1, len(rec.recipe))
        self.assertEqual("exec_in_pod", rec.recipe[0]["tool"])
        self.assertEqual({"cmd": "echo hi", "timeout_s": 30},
                         rec.recipe[0]["args"])
        # Delegated — sb saw the call
        self.assertEqual(["echo hi"], sb.runs)

    def test_records_write_file_to_pod(self):
        sb = FakeSandbox()
        rec = tb.TemplateRecorder(sb)
        rec.write_file_to_pod("/etc/x.conf", "value=1")
        self.assertEqual(
            [{"tool": "write_file_to_pod",
              "args": {"path": "/etc/x.conf", "content": "value=1"}}],
            rec.recipe)
        self.assertEqual([("/etc/x.conf", "value=1")], sb.writes)

    def test_records_install_package(self):
        sb = FakeSandbox(
            {"apt-get install": _Run(stdout="installed", returncode=0)})
        rec = tb.TemplateRecorder(sb)
        rec.install_package("openjdk-8-jdk", timeout_s=900)
        self.assertEqual(
            [{"tool": "install_package",
              "args": {"name": "openjdk-8-jdk", "timeout_s": 900}}],
            rec.recipe)
        self.assertTrue(sb.runs)   # apt-get command was issued
        self.assertIn("apt-get install", sb.runs[-1])

    def test_install_package_default_timeout(self):
        """Default timeout is 600s; recorded in args for provenance."""
        sb = FakeSandbox({"apt-get install": _Run(returncode=0)})
        rec = tb.TemplateRecorder(sb)
        rec.install_package("curl")
        self.assertEqual({"name": "curl", "timeout_s": 600},
                         rec.recipe[0]["args"])

    def test_records_http_probe(self):
        sb = FakeSandbox(
            {"curl": _Run(stdout="HTTP/1.1 200 OK\n", returncode=0)})
        rec = tb.TemplateRecorder(sb)
        rec.http_probe("http://127.0.0.1:8080/", method="POST",
                       headers={"content-type": "application/json"},
                       body="{}")
        self.assertEqual(1, len(rec.recipe))
        r0 = rec.recipe[0]
        self.assertEqual("http_probe", r0["tool"])
        self.assertEqual("http://127.0.0.1:8080/", r0["args"]["url"])
        self.assertEqual("POST", r0["args"]["method"])
        self.assertEqual({"content-type": "application/json"},
                         r0["args"]["headers"])

    def test_exec_or_raise_on_zero_exit_passes(self):
        sb = FakeSandbox({"true": _Run(stdout="", returncode=0)})
        rec = tb.TemplateRecorder(sb)
        rec.exec_or_raise("true")   # must not raise
        self.assertEqual(1, len(rec.recipe))
        self.assertEqual("exec_in_pod", rec.recipe[0]["tool"])

    def test_exec_or_raise_on_nonzero_raises_toolerror(self):
        sb = FakeSandbox({"false": _Run(returncode=1, stderr="bad")})
        rec = tb.TemplateRecorder(sb)
        from patchwing.tools import ToolError
        with self.assertRaisesRegex(ToolError, "exec_in_pod exit non-zero"):
            rec.exec_or_raise("false")
        # Call was still recorded (provenance intact even on raise)
        self.assertEqual(1, len(rec.recipe))

    def test_install_or_raise_on_zero_exit_passes(self):
        sb = FakeSandbox(
            {"apt-get install": _Run(stdout="ok", returncode=0)})
        rec = tb.TemplateRecorder(sb)
        rec.install_or_raise("curl")
        self.assertEqual(1, len(rec.recipe))

    def test_install_or_raise_on_nonzero_raises_toolerror(self):
        sb = FakeSandbox(
            {"apt-get install": _Run(returncode=100, stderr="404 not found")})
        rec = tb.TemplateRecorder(sb)
        from patchwing.tools import ToolError
        with self.assertRaisesRegex(ToolError,
                                    "install_package exit non-zero"):
            rec.install_or_raise("nonexistent-package-XYZ")

    def test_recipe_is_ordered(self):
        sb = FakeSandbox(
            {"apt-get install": _Run(returncode=0),
             "curl": _Run(stdout="HTTP/1.1 200\n", returncode=0)})
        rec = tb.TemplateRecorder(sb)
        rec.install_package("curl")
        rec.exec_in_pod("mkdir /opt/app")
        rec.write_file_to_pod("/opt/app/x", "y")
        rec.http_probe("http://127.0.0.1:8080/")
        tools = [step["tool"] for step in rec.recipe]
        self.assertEqual(
            ["install_package", "exec_in_pod",
             "write_file_to_pod", "http_probe"],
            tools)


# --- BuildFailed / VerificationFailed ------------------------------------

class BuildFailedTest(unittest.TestCase):

    def test_carries_stage_message_stdout_tail(self):
        e = tb.BuildFailed("commit", "podman not found",
                           stdout_tail="Error: no such thing")
        self.assertEqual("commit", e.stage)
        self.assertEqual("podman not found", e.message)
        self.assertIn("no such thing", e.stdout_tail)
        self.assertIn("commit: podman not found", str(e))

    def test_verification_failed_is_a_buildfailed(self):
        e = tb.VerificationFailed("verify_expect_mismatch",
                                  "did not match", stdout_tail="curl: 7")
        self.assertIsInstance(e, tb.BuildFailed)
        self.assertEqual("verify_expect_mismatch", e.stage)


# --- build_template happy + failure paths --------------------------------

class BuildTemplateHappyPathTest(unittest.TestCase):
    """Every external dependency (sandbox.make, subprocess.run,
    provision.commit_pod) mocked. Verifies the persist path + result."""

    def test_success_persists_row_and_returns_result(self):
        store, path = _mk_store()
        try:
            build_pod = FakeSandbox()
            verify_pod = FakeSandbox(
                {"curl": _Run(
                    stdout="HTTP/1.1 200 OK\nServer: Apache Tomcat/9.0\n",
                    returncode=0)})
            # sandbox.make returns build_pod first (for build), then
            # verify_pod (for verification). We identify by the image
            # in the spec.
            def fake_make(cfg, workdir, spec, persist=False):
                img = spec["target"]["image"]
                return build_pod if img == "ubuntu:22.04" else verify_pod

            def fake_commit(sb, tag):
                return tag  # no-op

            def recipe_fn(rec):
                rec.install_package("openjdk-8-jdk")
                rec.install_package("maven")
                return {
                    "verification_cmd":
                        "/opt/tomcat9/bin/startup.sh && sleep 10 && "
                        "curl -sSi http://127.0.0.1:8080/",
                    "verification_expect": r"HTTP/1\.1 200.*Apache Tomcat",
                }

            with mock.patch.object(sandbox_mod, "make", side_effect=fake_make), \
                 mock.patch.object(provision_mod, "commit_pod",
                                   side_effect=fake_commit), \
                 mock.patch.object(
                     tb, "_image_digest",
                     return_value="sha256:" + "a"*64), \
                 mock.patch.object(
                     tb, "_image_size_bytes", return_value=1_234_567):
                result = tb.build_template(
                    store=store, sandbox_config=_FakeSbxCfg(),
                    name="tomcat-jdk8",
                    description="JDK 8 + Maven + Tomcat 9",
                    base_image="ubuntu:22.04",
                    cve_class_hint="java-servlet-web-rce",
                    recipe_fn=recipe_fn)

            self.assertIsInstance(result, tb.BuildResult)
            self.assertEqual(2, result.turns)
            self.assertEqual("sha256:" + "a"*64, result.image_digest)
            self.assertEqual(1_234_567, result.image_size_bytes)
            # Persisted row
            t = store.get_template("tomcat-jdk8")
            self.assertIsNotNone(t)
            self.assertEqual("patchwing-template:tomcat-jdk8", t.image_tag)
            self.assertEqual(2, t.recipe_turn_count)
            # Recipe captured in order
            recipe = json.loads(t.recipe_json)
            self.assertEqual(
                ["install_package", "install_package"],
                [step["tool"] for step in recipe])
            # Verification recorded
            self.assertEqual(1, t.last_verified_ok)
            self.assertIn("Apache Tomcat", t.last_verified_note)
            # Both pods cleaned up
            self.assertTrue(build_pod.cleaned)
            self.assertTrue(verify_pod.cleaned)
        finally:
            store.close()
            _rm(path)


class BuildTemplateFailurePathsTest(unittest.TestCase):

    def _run_expecting_failure(self, recipe_fn, *,
                               verify_stdout="",
                               digest_side_effect=None,
                               commit_side_effect=None,
                               make_side_effect=None):
        """Helper: run build_template with mocked deps, return the
        raised exception + the store so callers can assert on both."""
        store, path = _mk_store()
        build_pod = FakeSandbox()
        verify_pod = FakeSandbox(
            {"": _Run(stdout=verify_stdout, returncode=0)})

        def fake_make(cfg, workdir, spec, persist=False):
            img = spec["target"]["image"]
            return build_pod if img == "ubuntu:22.04" else verify_pod

        digest_mock = (mock.patch.object(
                           tb, "_image_digest",
                           side_effect=digest_side_effect)
                       if digest_side_effect is not None
                       else mock.patch.object(
                           tb, "_image_digest",
                           return_value="sha256:" + "a"*64))
        commit_mock = (mock.patch.object(
                           provision_mod, "commit_pod",
                           side_effect=commit_side_effect)
                       if commit_side_effect is not None
                       else mock.patch.object(
                           provision_mod, "commit_pod",
                           return_value="ok"))
        make_mock = (mock.patch.object(
                         sandbox_mod, "make",
                         side_effect=make_side_effect or fake_make))

        removed = []
        remove_mock = mock.patch.object(
            tb, "_remove_image",
            side_effect=lambda backend, tag: removed.append(tag))
        size_mock = mock.patch.object(
            tb, "_image_size_bytes", return_value=1_000_000)

        with make_mock, commit_mock, digest_mock, remove_mock, size_mock:
            try:
                tb.build_template(
                    store=store, sandbox_config=_FakeSbxCfg(),
                    name="test-template",
                    description="test",
                    base_image="ubuntu:22.04",
                    cve_class_hint=None,
                    recipe_fn=recipe_fn)
            except tb.BuildFailed as e:
                return e, store, path, removed
            raise AssertionError("build_template did not raise")

    def test_verification_mismatch_raises_and_removes_and_no_persist(self):
        def recipe_fn(rec):
            rec.install_package("curl")
            return {"verification_cmd": "curl x",
                    "verification_expect": r"Apache Tomcat"}
        exc, store, path, removed = self._run_expecting_failure(
            recipe_fn, verify_stdout="HTTP/1.1 200\nnot the expected string")
        try:
            self.assertIsInstance(exc, tb.VerificationFailed)
            self.assertEqual("verify_expect_mismatch", exc.stage)
            # Image was removed
            self.assertEqual(["patchwing-template:test-template"], removed)
            # DB row NOT persisted
            self.assertIsNone(store.get_template("test-template"))
            self.assertEqual([], store.list_templates())
            # Stdout tail carries what actually came back
            self.assertIn("not the expected string", exc.stdout_tail)
        finally:
            store.close(); _rm(path)

    def test_recipe_fn_raise_wrapped_as_buildfailed(self):
        def recipe_fn(rec):
            rec.install_package("curl")
            raise RuntimeError("model changed its mind")
        exc, store, path, removed = self._run_expecting_failure(recipe_fn)
        try:
            self.assertEqual("recipe", exc.stage)
            self.assertIn("model changed its mind", exc.message)
            self.assertIsNone(store.get_template("test-template"))
            # Nothing committed → nothing to remove
            self.assertEqual([], removed)
        finally:
            store.close(); _rm(path)

    def test_recipe_fn_non_dict_return_raises(self):
        def recipe_fn(rec):
            rec.install_package("x")
            return "verify_cmd_here"          # wrong type
        exc, store, path, removed = self._run_expecting_failure(recipe_fn)
        try:
            self.assertEqual("recipe", exc.stage)
            self.assertIn("must return a dict", exc.message)
            self.assertEqual([], removed)
            self.assertIsNone(store.get_template("test-template"))
        finally:
            store.close(); _rm(path)

    def test_recipe_fn_missing_verification_fields_raises(self):
        def recipe_fn(rec):
            rec.install_package("x")
            return {}
        exc, store, path, removed = self._run_expecting_failure(recipe_fn)
        try:
            self.assertEqual("recipe", exc.stage)
            self.assertIn("verification_cmd", exc.message)
            self.assertEqual([], removed)
        finally:
            store.close(); _rm(path)

    def test_recipe_fn_bad_regex_raises(self):
        def recipe_fn(rec):
            rec.install_package("x")
            return {"verification_cmd": "echo hi",
                    "verification_expect": r"[invalid("}  # bad regex
        exc, store, path, removed = self._run_expecting_failure(recipe_fn)
        try:
            self.assertEqual("recipe", exc.stage)
            self.assertIn("not a valid regex", exc.message)
        finally:
            store.close(); _rm(path)

    def test_commit_failure_raises(self):
        def recipe_fn(rec):
            rec.install_package("x")
            return {"verification_cmd": "echo hi",
                    "verification_expect": r"."}

        def bad_commit(sb, tag):
            raise sandbox_mod.SandboxError("commit refused")
        exc, store, path, removed = self._run_expecting_failure(
            recipe_fn, commit_side_effect=bad_commit)
        try:
            self.assertEqual("commit", exc.stage)
            self.assertIn("commit refused", exc.message)
            # Nothing committed → nothing to remove
            self.assertEqual([], removed)
            self.assertIsNone(store.get_template("test-template"))
        finally:
            store.close(); _rm(path)

    def test_duplicate_name_refused_before_pod_creation(self):
        store, path = _mk_store()
        try:
            # Insert an existing row first
            store.add_template(
                name="already-exists", description="x",
                base_image="ubuntu:22.04",
                image_tag=tpl_mod.image_tag_for("already-exists"),
                recipe_json="[]", recipe_turn_count=0,
                verification_cmd="echo hi",
                verification_expect=".",
                builder_version=tpl_mod.BUILDER_VERSION_CURRENT)

            # Now build_template with same name — should refuse EARLY,
            # before touching sandbox.make.
            with mock.patch.object(sandbox_mod, "make") as mmake:
                with self.assertRaises(tb.BuildFailed) as ctx:
                    tb.build_template(
                        store=store, sandbox_config=_FakeSbxCfg(),
                        name="already-exists",
                        description="second attempt",
                        base_image="ubuntu:22.04",
                        cve_class_hint=None,
                        recipe_fn=lambda rec: {})
                self.assertEqual("precheck", ctx.exception.stage)
                mmake.assert_not_called()
        finally:
            store.close(); _rm(path)


# --- subprocess helpers --------------------------------------------------

class SubprocessHelperTest(unittest.TestCase):

    def test_image_digest_success(self):
        with mock.patch("subprocess.run",
                        return_value=_completed(
                            stdout="sha256:" + "a"*64 + "\n",
                            returncode=0)):
            d = tb._image_digest("podman", "some:tag")
            self.assertEqual("sha256:" + "a"*64, d)

    def test_image_digest_backend_missing_raises(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(tb.BuildFailed) as ctx:
                tb._image_digest("podman", "some:tag")
            self.assertEqual("inspect", ctx.exception.stage)

    def test_image_digest_empty_raises(self):
        with mock.patch("subprocess.run",
                        return_value=_completed(stdout="", returncode=0)):
            with self.assertRaises(tb.BuildFailed):
                tb._image_digest("podman", "some:tag")

    def test_image_size_bytes_returns_int(self):
        with mock.patch("subprocess.run",
                        return_value=_completed(
                            stdout="12345\n", returncode=0)):
            self.assertEqual(12345,
                             tb._image_size_bytes("podman", "some:tag"))

    def test_image_size_bytes_none_on_failure(self):
        with mock.patch("subprocess.run",
                        return_value=_completed(returncode=1)):
            self.assertIsNone(tb._image_size_bytes("podman", "x"))

    def test_remove_image_never_raises(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
            tb._remove_image("podman", "x")   # must not raise


if __name__ == "__main__":
    unittest.main(verbosity=2)
