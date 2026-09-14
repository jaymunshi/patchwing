"""Provision-specific network override tests.

Two guarantees:
  1. `cfg.sandbox.provision_network` only affects the provision stage;
     reproduce/patch/verify/anything else keeps `cfg.sandbox.network`
     (default "none") — no leak.
  2. `provision_egress_host` events fire per unique host touched by
     the provision loop, so a future allowlist can be built from real
     observed data. Non-enforcing — pure audit.
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

from patchwing import provision as provision_mod              # noqa: E402
from patchwing import sandbox as sandbox_mod                  # noqa: E402
from patchwing import stages                                  # noqa: E402
from patchwing.config import SandboxConfig                    # noqa: E402


# --- SandboxConfig new field --------------------------------------------

class SandboxConfigProvisionNetworkTest(unittest.TestCase):

    def test_default_is_none(self):
        s = SandboxConfig()
        self.assertEqual("none", s.provision_network)
        self.assertEqual("none", s.network)   # unchanged default

    def test_can_be_set_to_bridge(self):
        s = SandboxConfig(provision_network="bridge")
        self.assertEqual("bridge", s.provision_network)
        # Default network stays "none" — provision override is orthogonal
        self.assertEqual("none", s.network)


# --- sandbox.make network kwarg -----------------------------------------

class SandboxMakeNetworkOverrideTest(unittest.TestCase):

    def test_network_kwarg_overrides_cfg_network(self):
        cfg = SandboxConfig(backend="podman", network="none",
                            provision_network="bridge")
        spec = {"target": {"image": "ubuntu:22.04", "mode": "in-image",
                           "root": "/"}}
        # No override → cfg.network = "none"
        sb = sandbox_mod.make(cfg, workdir=tempfile.mkdtemp(),
                              spec=spec, persist=False)
        self.assertEqual("none", sb.network)
        # Override → "bridge"
        sb2 = sandbox_mod.make(cfg, workdir=tempfile.mkdtemp(),
                               spec=spec, persist=False, network="bridge")
        self.assertEqual("bridge", sb2.network)

    def test_none_kwarg_falls_through_to_cfg_default(self):
        """network=None (not passed) falls through to cfg.network."""
        cfg = SandboxConfig(backend="podman", network="host")
        spec = {"target": {"image": "x", "mode": "in-image", "root": "/"}}
        sb = sandbox_mod.make(cfg, workdir=tempfile.mkdtemp(),
                              spec=spec, network=None)
        self.assertEqual("host", sb.network)


# --- other stages don't leak provision_network --------------------------

class OtherStagesUnaffectedTest(unittest.TestCase):
    """The load-bearing test: even with provision_network='bridge',
    every non-provision stage's sandbox.make call must use network='none'
    (or whatever cfg.sandbox.network is set to — 'none' by default),
    NEVER the provision-specific value. Regression guard against a
    future refactor that would collapse the two fields."""

    def test_default_sandbox_call_gets_none_not_provision_network(self):
        """Simulate the shape of _sandbox() in reproduce/patch/verify:
        no network= kwarg passed. Must resolve to cfg.network, ignoring
        cfg.provision_network entirely."""
        cfg = SandboxConfig(backend="podman", network="none",
                            provision_network="bridge")
        spec = {"target": {"image": "x", "mode": "in-image", "root": "/"}}
        sb = sandbox_mod.make(cfg, workdir=tempfile.mkdtemp(), spec=spec)
        self.assertEqual("none", sb.network)

    def test_reproduce_stage_shape_uses_default_network(self):
        """reproduce's _sandbox() call at stages.py:1151 does NOT pass
        network=. The kwarg default (None) must fall through to
        cfg.network, not cfg.provision_network. Assert by inspecting
        the call to sandbox.make."""
        cfg = SandboxConfig(backend="podman", network="none",
                            provision_network="bridge")

        class _Ctx: pass
        ctx = _Ctx()
        ctx.config = mock.Mock()
        ctx.config.sandbox = cfg
        ctx.workdir = "/tmp"
        seen_networks = []

        def spy_make(cfg_arg, **kw):
            seen_networks.append(kw.get("network"))
            return mock.Mock()

        with mock.patch.object(sandbox_mod, "make", side_effect=spy_make):
            # Simulate the reproduce-shape call — no network= kwarg
            stages._sandbox(ctx, {"target": {"image": "x", "mode": "in-image"}},
                            finding=None, persist=True)
            # Simulate the provision-shape call — explicit network=
            stages._sandbox(ctx, {"target": {"image": "y", "mode": "in-image"}},
                            finding=None, persist=True, network="bridge")
        self.assertEqual([None, "bridge"], seen_networks)
        # sandbox.make with network=None → falls through to cfg.network
        # (proved in test_none_kwarg_falls_through_to_cfg_default above)


# --- host extraction regex ----------------------------------------------

class ExtractHostsFromCmdTest(unittest.TestCase):

    def test_http_url(self):
        self.assertEqual(
            {"github.com"},
            provision_mod._extract_hosts_from_cmd(
                "curl -sSL https://github.com/foo/bar.git"))

    def test_wget_url(self):
        self.assertEqual(
            {"archive.apache.org"},
            provision_mod._extract_hosts_from_cmd(
                "wget -q https://archive.apache.org/dist/tomcat/x.tgz"))

    def test_git_clone_url(self):
        # https git clone
        self.assertEqual(
            {"github.com"},
            provision_mod._extract_hosts_from_cmd(
                "git clone https://github.com/apache/struts.git"))
        # ssh-style git
        self.assertEqual(
            {"github.com"},
            provision_mod._extract_hosts_from_cmd(
                "git clone git@github.com:apache/struts.git"))

    def test_multiple_hosts(self):
        hosts = provision_mod._extract_hosts_from_cmd(
            "wget https://a.example && curl https://b.example.org/x")
        self.assertIn("a.example", hosts)
        self.assertIn("b.example.org", hosts)

    def test_no_url_returns_empty_set(self):
        self.assertEqual(set(),
                         provision_mod._extract_hosts_from_cmd(
                             "ls -la /opt && ps aux"))

    def test_empty_or_non_string_safe(self):
        self.assertEqual(set(), provision_mod._extract_hosts_from_cmd(""))
        self.assertEqual(set(), provision_mod._extract_hosts_from_cmd(None))
        self.assertEqual(set(), provision_mod._extract_hosts_from_cmd(42))


# --- egress_host events fire per unique host in the loop ---------------

class ProvisionEgressHostEventsTest(unittest.TestCase):
    """End-to-end via run_provision_loop: Kimi runs three exec_in_pod
    commands, each touching different hosts. Assert one event per
    unique host, no duplicates."""

    def _draft(self):
        return {"endpoint_path_norm": "/x", "method": "GET",
                "expected_status_red": 200,
                "evidence_rules": [{"name": "r",
                                    "kind": "response_body_regex",
                                    "pattern": "x"}]}

    def test_one_event_per_unique_host(self):
        # Import fixtures from test_provision.py
        from test_provision import (_FakeCtx, _FakeFinding, FakeClient,
                                    FakeSandbox, _Run)
        ctx = _FakeCtx()
        f = _FakeFinding("egress-t1")
        client = FakeClient([
            {"tool_calls": [{"tool": "exec_in_pod",
                             "args": {"cmd": "git clone https://github.com/x/y",
                                      "timeout_s": 300}}]},
            {"tool_calls": [{"tool": "exec_in_pod",
                             "args": {"cmd": "wget https://archive.apache.org/dist/x.tgz",
                                      "timeout_s": 300}}]},
            # Duplicate github.com touch — must NOT re-emit
            {"tool_calls": [{"tool": "exec_in_pod",
                             "args": {"cmd": "curl -sSL https://github.com/other/repo",
                                      "timeout_s": 60}}]},
            {"done": True, "target_url": "http://x/y",
             "reproduce_command": "curl x"},
        ])
        sb = FakeSandbox({
            "git clone": _Run(stdout="cloned"),
            "wget": _Run(stdout="fetched"),
            "curl": _Run(stdout="ok"),
        })
        provision_mod.run_provision_loop(
            ctx, f, client, sb, self._draft(),
            base_image="ubuntu:22.04", max_turns=10)
        egress_events = [e for e in ctx.store.events
                         if e["kind"] == "provision_egress_host"]
        hosts = sorted(json.loads(e["meta"])["host"] for e in egress_events)
        # One event per UNIQUE host, alphabetically:
        self.assertEqual(["archive.apache.org", "github.com"], hosts)


if __name__ == "__main__":
    unittest.main(verbosity=2)
