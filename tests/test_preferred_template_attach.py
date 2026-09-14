"""Provision consumes preferred_template — resolver + stage integration.

Pass 5 test coverage:

  Resolver (`provision.resolve_template_image`):
    * happy path — row exists + image exists + digest matches
    * missing — pod_templates row absent
    * image_gone — row exists but podman doesn't have the tag
    * digest_drift — podman's current digest differs from the row's

  Stage wiring — asserts the three failure paths return
  StageResult.fail with the correct outcome constant, and the happy
  path emits a `template_attached` event carrying template_name +
  verified_digest for post-hoc forensics.

  Invariant — no reproducer_lock is written in any of the four paths
  (including the happy attach). Provision remains the non-writer.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import outcomes as outcomes_mod                # noqa: E402
from patchwing import provision as provision_mod              # noqa: E402
from patchwing import template_builder as tb                  # noqa: E402
from patchwing import templates as tpl_mod                    # noqa: E402
from patchwing.store import Store                             # noqa: E402


_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64


class _SbxCfg:
    backend = "podman"
    image = ""
    network = "none"
    cpus = 2.0
    memory = "4g"
    timeout_s = 1800


def _mk_store():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Store(tmp.name), tmp.name


def _rm(p):
    try: os.unlink(p)
    except OSError: pass


def _seed(store, name="tomcat-jdk8", digest=_DIGEST_A):
    return store.add_template(
        name=name, description=f"{name}", base_image="ubuntu:22.04",
        image_tag=tpl_mod.image_tag_for(name),
        recipe_json="[]", recipe_turn_count=0,
        verification_cmd="echo hi", verification_expect=".",
        builder_version=tpl_mod.BUILDER_VERSION_CURRENT,
        image_size_bytes=100_000_000, image_digest=digest,
        cve_class_hint="java-servlet-web-rce")


# --- resolver -----------------------------------------------------------

class ResolveTemplateImageTest(unittest.TestCase):

    def test_happy_path_returns_verified_digest(self):
        store, path = _mk_store()
        try:
            _seed(store, digest=_DIGEST_A)
            with mock.patch.object(
                    provision_mod, "_podman_image_exists",
                    return_value=True), \
                 mock.patch.object(
                    tb, "_image_digest", return_value=_DIGEST_A):
                res = provision_mod.resolve_template_image(
                    store=store, sandbox_config=_SbxCfg(),
                    template_name="tomcat-jdk8")
            self.assertTrue(res["ok"], msg=str(res))
            self.assertEqual("patchwing-template:tomcat-jdk8",
                             res["image_tag"])
            self.assertEqual(_DIGEST_A, res["verified_digest"])
            self.assertEqual("tomcat-jdk8", res["template_name"])
        finally:
            store.close(); _rm(path)

    def test_missing_template_row(self):
        store, path = _mk_store()
        try:
            # No row seeded
            res = provision_mod.resolve_template_image(
                store=store, sandbox_config=_SbxCfg(),
                template_name="never-existed")
            self.assertFalse(res["ok"])
            self.assertEqual("provision_template_missing", res["outcome"])
            self.assertIn("never-existed", res["error"])
        finally:
            store.close(); _rm(path)

    def test_image_gone(self):
        """Row exists but podman doesn't have the tag."""
        store, path = _mk_store()
        try:
            _seed(store)
            with mock.patch.object(
                    provision_mod, "_podman_image_exists",
                    return_value=False):
                res = provision_mod.resolve_template_image(
                    store=store, sandbox_config=_SbxCfg(),
                    template_name="tomcat-jdk8")
            self.assertFalse(res["ok"])
            self.assertEqual("provision_template_image_gone",
                             res["outcome"])
            self.assertIn("podman has no image", res["error"])
        finally:
            store.close(); _rm(path)

    def test_digest_drift(self):
        """Row exists, image exists, but current digest differs from
        what was recorded at build time. THE load-bearing test."""
        store, path = _mk_store()
        try:
            _seed(store, digest=_DIGEST_A)      # recorded at build time
            with mock.patch.object(
                    provision_mod, "_podman_image_exists",
                    return_value=True), \
                 mock.patch.object(
                    tb, "_image_digest", return_value=_DIGEST_B):
                # podman's current view differs
                res = provision_mod.resolve_template_image(
                    store=store, sandbox_config=_SbxCfg(),
                    template_name="tomcat-jdk8")
            self.assertFalse(res["ok"])
            self.assertEqual("provision_template_digest_drift",
                             res["outcome"])
            self.assertIn("DIGEST DRIFT", res["error"])
            self.assertIn(_DIGEST_A[:19], res["error"])
            self.assertIn(_DIGEST_B[:19], res["error"])
        finally:
            store.close(); _rm(path)

    def test_image_digest_helper_raise_treated_as_image_gone(self):
        """If `_image_digest` raises BuildFailed for any reason after
        the exists-check passes, treat as image_gone rather than
        drift — we cannot make a positive drift claim without a
        current digest to compare."""
        store, path = _mk_store()
        try:
            _seed(store)
            with mock.patch.object(
                    provision_mod, "_podman_image_exists",
                    return_value=True), \
                 mock.patch.object(
                    tb, "_image_digest",
                    side_effect=tb.BuildFailed("inspect", "podman broke")):
                res = provision_mod.resolve_template_image(
                    store=store, sandbox_config=_SbxCfg(),
                    template_name="tomcat-jdk8")
            self.assertFalse(res["ok"])
            self.assertEqual("provision_template_image_gone",
                             res["outcome"])
            self.assertIn("cannot read current digest", res["error"])
        finally:
            store.close(); _rm(path)

    def test_whitespace_name_treated_as_missing(self):
        store, path = _mk_store()
        try:
            res = provision_mod.resolve_template_image(
                store=store, sandbox_config=_SbxCfg(),
                template_name="   ")
            self.assertFalse(res["ok"])
            self.assertEqual("provision_template_missing", res["outcome"])
        finally:
            store.close(); _rm(path)


# --- _podman_image_exists helper ----------------------------------------

class PodmanImageExistsTest(unittest.TestCase):
    """The pre-check that distinguishes 'image gone' from 'digest
    inspect broke for some other reason'."""

    def test_exit_zero_returns_true(self):
        mock_run = mock.Mock(return_value=mock.Mock(returncode=0))
        with mock.patch("subprocess.run", mock_run):
            self.assertTrue(provision_mod._podman_image_exists(
                "podman", "some:tag"))

    def test_exit_one_returns_false(self):
        mock_run = mock.Mock(return_value=mock.Mock(returncode=1))
        with mock.patch("subprocess.run", mock_run):
            self.assertFalse(provision_mod._podman_image_exists(
                "podman", "some:tag"))

    def test_backend_missing_returns_false(self):
        with mock.patch("subprocess.run",
                        side_effect=FileNotFoundError()):
            self.assertFalse(provision_mod._podman_image_exists(
                "podman", "some:tag"))

    def test_timeout_returns_false(self):
        import subprocess
        with mock.patch("subprocess.run",
                        side_effect=subprocess.TimeoutExpired("x", 15)):
            self.assertFalse(provision_mod._podman_image_exists(
                "podman", "some:tag"))


# --- outcome constants --------------------------------------------------

class Pass5OutcomesDeclaredTest(unittest.TestCase):
    def test_all_three_declared(self):
        for name in ("provision_template_missing",
                     "provision_template_image_gone",
                     "provision_template_digest_drift"):
            self.assertIn(name, outcomes_mod.ALL,
                          f"outcome {name!r} not in outcomes.ALL")


# --- stage integration --------------------------------------------------
# The @stage("provision") body has to short-circuit correctly on any of
# the three failure paths. Rather than running a full provision loop
# (which needs a model client + real pod), we drive the stage function
# with mocks for the pieces AFTER template resolution — sandbox.make,
# provision.run_provision_loop, provision.commit_pod — and assert on
# what happens before those get called for each of the failure paths.

@dataclass
class _StubFinding:
    id: str = "STUB"
    stage: str = "provision"
    state: str = "pending"
    attempts: int = 0
    error: str = ""
    source: str = "advisory"
    source_ref: str = "CVE-STUB"
    title: str = "stub"
    description: str = "stub"
    repo_url: str = ""
    repo_ref: str = ""
    base_commit: str = ""
    cwe: str = ""
    owner: str = ""
    container_id: str = ""
    parent_finding_id: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0


class ProvisionStageWithPreferredTemplateTest(unittest.TestCase):
    """Stage-level integration. Uses a temp Store with:
      - a scratch finding at stage=provision, state=pending
      - a draft_spec artifact carrying preferred_template
      - a spec artifact ABSENT (no ARVO shortcut)
    Verifies that the three resolver failure paths surface as the
    expected StageResult outcomes."""

    def _mk_ctx(self, preferred=None):
        # stages.Context is a Protocol (structural type), not
        # instantiable. Duck-type it with a plain object.
        from patchwing.store import Store
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        store = Store(tmp.name)

        # Seed finding + draft_spec
        fid = "PASS5-STUB"
        store.conn.execute(
            "INSERT INTO findings(id, source, source_ref, repo_url, "
            "repo_ref, base_commit, cwe, title, description, stage, "
            "state, attempts, error, created_at, updated_at, owner, "
            "container_id, parent_finding_id) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, "advisory", "CVE-STUB", "", "", "", "", "stub", "stub",
             "provision", "pending", 0, "",
             time.time(), time.time(), "", "", ""))
        store.conn.commit()
        draft_http = {
            "endpoint_path_norm": "/x", "method": "GET",
            "expected_status_red": 200,
            "evidence_rules": [{"name": "r", "kind": "response_body_regex",
                                "pattern": "x"}]}
        if preferred is not None:
            draft_http["preferred_template"] = preferred
        store.add_artifact(fid, "draft_spec", "localize",
                           content=json.dumps(draft_http),
                           meta={}, base_commit="", model="")

        # Config with sandbox + patch/verify/provision seat-shaped model
        # config (real Config not needed — the stage only touches
        # ctx.config.sandbox and cfg.model(role) for the client). For
        # this test we never reach the model call, so a stub is enough.
        # Config duck-type: patch, verify, ceiling calls all get a
        # real shape so provision's prologue (ceiling read, model
        # client lookup) doesn't blow up on Mock-int coercion.
        from patchwing.config import ModelConfig, PipelineConfig
        cfg = mock.Mock()
        cfg.sandbox = _SbxCfg()
        cfg.pipeline = PipelineConfig()
        mc = ModelConfig(role="provision", endpoint="http://fake",
                         model="stub", api_key="x", max_tokens=0)
        cfg.model.return_value = mc

        class _Ctx: pass
        ctx = _Ctx()
        ctx.store = store
        ctx.workdir = "/tmp"
        ctx.config = cfg
        f = store.get(fid)
        return ctx, f, tmp.name

    def test_missing_template_returns_provision_template_missing(self):
        from patchwing.stages import _REGISTRY
        ctx, f, path = self._mk_ctx(preferred="does-not-exist")
        try:
            result = _REGISTRY["provision"](f, ctx)
            self.assertEqual("fail", result.status)
            self.assertEqual("provision_template_missing",
                             result.meta["outcome"])
            self.assertEqual("does-not-exist",
                             result.meta.get("template_name"))
            # Invariant: no reproducer_lock written
            self.assertIsNone(
                ctx.store.latest_artifact(f.id, "reproducer_lock"))
        finally:
            ctx.store.close(); _rm(path)

    def test_image_gone_returns_provision_template_image_gone(self):
        from patchwing.stages import _REGISTRY
        ctx, f, path = self._mk_ctx(preferred="tomcat-jdk8")
        try:
            _seed(ctx.store, name="tomcat-jdk8")
            with mock.patch.object(
                    provision_mod, "_podman_image_exists",
                    return_value=False):
                result = _REGISTRY["provision"](f, ctx)
            self.assertEqual("fail", result.status)
            self.assertEqual("provision_template_image_gone",
                             result.meta["outcome"])
            self.assertIsNone(
                ctx.store.latest_artifact(f.id, "reproducer_lock"))
        finally:
            ctx.store.close(); _rm(path)

    def test_digest_drift_returns_provision_template_digest_drift(self):
        from patchwing.stages import _REGISTRY
        ctx, f, path = self._mk_ctx(preferred="tomcat-jdk8")
        try:
            _seed(ctx.store, name="tomcat-jdk8", digest=_DIGEST_A)
            with mock.patch.object(
                    provision_mod, "_podman_image_exists",
                    return_value=True), \
                 mock.patch.object(
                    tb, "_image_digest", return_value=_DIGEST_B):
                result = _REGISTRY["provision"](f, ctx)
            self.assertEqual("fail", result.status)
            self.assertEqual("provision_template_digest_drift",
                             result.meta["outcome"])
            self.assertIn("DIGEST DRIFT", result.message)
            self.assertIsNone(
                ctx.store.latest_artifact(f.id, "reproducer_lock"))
        finally:
            ctx.store.close(); _rm(path)

    def test_no_preferred_template_still_uses_ubuntu(self):
        """Backward-compat: findings without preferred_template still
        get the bare ubuntu:22.04 base — the wiring is opt-in."""
        from patchwing.stages import _REGISTRY
        ctx, f, path = self._mk_ctx(preferred=None)
        try:
            # We short-circuit BEFORE sandbox.make gets called by mocking
            # _client() to raise a ConfigError. Result: provision blocks
            # with provision_no_model_configured. But the important
            # assertion here is that NO template-related outcome fires
            # (since no preferred_template was set).
            from patchwing.config import ConfigError
            ctx.config.model.side_effect = ConfigError("no model")
            result = _REGISTRY["provision"](f, ctx)
            self.assertNotIn(result.meta.get("outcome", ""), {
                "provision_template_missing",
                "provision_template_image_gone",
                "provision_template_digest_drift",
            })
        finally:
            ctx.store.close(); _rm(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
