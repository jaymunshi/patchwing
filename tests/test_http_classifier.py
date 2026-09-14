"""HTTP-shape classifier — unit tests for the dispatched sibling of the
sanitizer path. Design: docs/http-classifier-design.md.

The trust story hinges on one property: a "red" HTTP reading must come
from EVIDENCE — a named regex hit in the response body/headers OR a
named side-channel observation. A bare 200 is not red. A curl that
"didn't error" is not red. These tests are what keeps that true.

If any of these fail, the provision line's trust story is broken from
the ground up.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import states                              # noqa: E402
from patchwing.states import (                            # noqa: E402
    EvidenceRule, HttpEvidence, HttpPristine, identity_hash_for)


# --- fixtures --------------------------------------------------------------

# One realistic rule set for a pass-1 eval-style RCE reproducer.
_RULES = (
    EvidenceRule(
        name="uid_reflection",
        kind="response_body_regex",
        pattern=r"uid=\d+\("),
    EvidenceRule(
        name="pwn_file_created",
        kind="side_channel_flag",
        pattern="True"),
)


def _pristine(status: int = 200, endpoint: str = "/eval",
              method: str = "GET", rules=_RULES,
              expected_green_statuses=None,
              body_fingerprint_negative_list=()) -> HttpPristine:
    """Build a pristine + its identity hash together, so identity is
    consistent with the input fields. This is exactly the caller-side
    pattern the sanitizer path uses (stages.py:1077-1084)."""
    h = identity_hash_for(endpoint, method, status, rules)
    return HttpPristine(
        endpoint_path_norm=endpoint,
        method=method,
        status=status,
        evidence_rules=rules,
        identity_hash=h,
        expected_green_statuses=expected_green_statuses,
        body_fingerprint_negative_list=body_fingerprint_negative_list,
    )


def _evidence(**overrides) -> HttpEvidence:
    """Base evidence: valid response, matches uid_reflection, side-channel
    fires. Override any field for a specific test."""
    defaults = dict(
        method="GET",
        endpoint_path="/eval",
        request_headers=(("host", "target"),),
        request_body_sha256="",
        status=200,
        response_headers=(("content-type", "text/plain"),),
        response_body="uid=0(root) gid=0(root) groups=0(root)\n",
        response_body_bytes=39,
        time_to_first_byte_s=0.023,
        total_s=0.045,
        transport_error="",
        transport_detail="",
        side_channel=(("pwn_file_created", "True"),),
    )
    defaults.update(overrides)
    return HttpEvidence(**defaults)


# --- router-level rejection tests -----------------------------------------

class RouterDispatchTest(unittest.TestCase):
    """The router MUST reject anything that would silently degrade to the
    wrong path. These aren't the classifier's happy-path — these keep the
    dispatch surface honest."""

    def test_missing_kind_raises_typeerror(self):
        with self.assertRaises(TypeError):
            states.classify()

    def test_positional_returncode_no_kind_raises_typeerror(self):
        """Old-style call. Must not silently succeed."""
        with self.assertRaises(TypeError):
            # noqa: exact old shape — three positional args
            states.classify(0, "output", "token")

    def test_unknown_kind_raises_valueerror(self):
        with self.assertRaises(ValueError):
            states.classify("sanitiser")   # British sp., not supported

    def test_http_kind_without_evidence_raises_typeerror(self):
        with self.assertRaises(TypeError):
            states.classify("http")

    def test_http_kind_without_rules_or_pristine_raises_typeerror(self):
        with self.assertRaises(TypeError):
            states.classify("http", http=_evidence())

    def test_http_kind_with_wrong_type_raises_typeerror(self):
        with self.assertRaises(TypeError):
            states.classify("http", http={"status": 200}, rules=_RULES)

    def test_sanitizer_still_works(self):
        r = states.classify("sanitizer", returncode=0,
                            output="all quiet", pristine_token="x")
        self.assertEqual("confirmed_green", r["state"])
        self.assertEqual("sanitizer", r["kind"])


# --- CONFIRMED_RED --------------------------------------------------------

class HttpConfirmedRedTest(unittest.TestCase):

    def test_body_regex_match_with_identity_match_is_red(self):
        p = _pristine()
        r = states.classify("http", http=_evidence(), pristine_http=p)
        self.assertEqual("confirmed_red", r["state"])
        self.assertEqual("http", r["kind"])
        self.assertIn("uid_reflection", r["http_evidence_hits"])
        self.assertIn("pwn_file_created", r["side_channel_hits"])
        self.assertTrue(r["id_matches_pristine"])
        self.assertEqual(p.identity_hash, r["observed_http_id"])

    def test_side_channel_flag_alone_is_red(self):
        """No body match, only side-channel flag → still red. Evidence
        is evidence regardless of channel."""
        p = _pristine()
        e = _evidence(response_body="no reflection in response",
                      response_body_bytes=27)
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("confirmed_red", r["state"])
        self.assertEqual((), r["http_evidence_hits"])
        self.assertEqual(("pwn_file_created",), r["side_channel_hits"])

    def test_body_regex_alone_is_red(self):
        """No side-channel, only body regex → still red."""
        p = _pristine()
        e = _evidence(side_channel=())
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("confirmed_red", r["state"])
        self.assertEqual(("uid_reflection",), r["http_evidence_hits"])
        self.assertEqual((), r["side_channel_hits"])

    def test_first_reproduce_with_rules_and_no_pristine_is_red(self):
        """The very first reproduce runs BEFORE the wall is frozen —
        there is no pristine to compare against. Rule match with
        extractable identity must still count as red; that is how the
        pristine gets established."""
        r = states.classify("http", http=_evidence(), rules=_RULES,
                            pristine_http=None)
        self.assertEqual("confirmed_red", r["state"])
        self.assertTrue(r["observed_http_id"])
        self.assertEqual("", r["pristine_http_id"])
        self.assertFalse(r["id_matches_pristine"])

    def test_response_header_regex_match_is_red(self):
        # Design §2: harness lowercases header names before passing.
        # Rule patterns match against the lowercased-names view.
        p = _pristine(rules=(EvidenceRule(
            name="server_reflects_ognl",
            kind="response_header_regex",
            pattern=r"x-reflected-ognl: uid="),))
        e = _evidence(
            response_headers=(("content-type", "text/plain"),
                              ("x-reflected-ognl", "uid=0(root)")),
            response_body="", response_body_bytes=0, side_channel=())
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("confirmed_red", r["state"])
        self.assertIn("server_reflects_ognl", r["http_evidence_hits"])


# --- CONFIRMED_GREEN ------------------------------------------------------

class HttpConfirmedGreenTest(unittest.TestCase):

    def test_no_rule_match_with_different_status_is_green(self):
        """Pristine at 200; patched target returns 400 with no rule hits
        → green under default expected-green (any status != pristine)."""
        p = _pristine(status=200)
        e = _evidence(status=400,
                      response_body='{"error":"input rejected"}',
                      response_body_bytes=26,
                      side_channel=())
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("confirmed_green", r["state"])
        self.assertEqual((), r["http_evidence_hits"])
        self.assertEqual((), r["side_channel_hits"])

    def test_no_rule_match_with_explicit_expected_status_is_green(self):
        p = _pristine(status=200, expected_green_statuses=frozenset({403}))
        e = _evidence(status=403, response_body="forbidden",
                      response_body_bytes=9, side_channel=())
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("confirmed_green", r["state"])

    def test_no_rule_match_no_pristine_is_green(self):
        """First reproduce with no rules matching. Honest label: no
        evidence of the bug here."""
        r = states.classify("http", http=_evidence(side_channel=(),
                            response_body="nothing to see"), rules=_RULES,
                            pristine_http=None)
        self.assertEqual("confirmed_green", r["state"])


# --- HARNESS_FAULT --------------------------------------------------------

class HttpHarnessFaultTest(unittest.TestCase):

    def test_connection_refused_is_harness_fault(self):
        p = _pristine()
        e = _evidence(status=0, response_body="", response_body_bytes=0,
                      time_to_first_byte_s=None, total_s=0.001,
                      transport_error="connection_refused",
                      transport_detail="target:8080")
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])
        self.assertIn("connection_refused", r["why"])

    def test_dns_failure_is_harness_fault(self):
        p = _pristine()
        e = _evidence(status=0, response_body="", response_body_bytes=0,
                      transport_error="dns_failure")
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])

    def test_tls_error_is_harness_fault(self):
        p = _pristine()
        e = _evidence(status=0, response_body="", response_body_bytes=0,
                      transport_error="tls_error")
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])

    def test_timeout_before_first_byte_is_harness_fault(self):
        p = _pristine()
        e = _evidence(status=0, response_body="", response_body_bytes=0,
                      time_to_first_byte_s=None, total_s=30.0,
                      transport_error="timeout_before_first_byte")
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])

    def test_container_never_listened_is_harness_fault(self):
        p = _pristine()
        e = _evidence(status=0, response_body="", response_body_bytes=0,
                      transport_error="container_never_listened")
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])

    def test_malformed_negative_status_is_harness_fault(self):
        p = _pristine()
        # bypass frozen dataclass validation the honest way
        e = HttpEvidence(method="GET", endpoint_path="/eval",
                         status=-1, response_body_bytes=0)
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])
        self.assertIn("malformed", r["why"])

    def test_status_matches_pristine_no_rules_matched_is_harness_fault(self):
        """No rule hits but the response came back at exactly the
        pristine's status. That is neither red (no evidence) nor green
        (indistinguishable from partial fix). Honest label."""
        p = _pristine(status=200)
        e = _evidence(status=200, response_body="all clear",
                      response_body_bytes=9, side_channel=())
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])
        self.assertIn("cannot distinguish", r["why"])

    def test_negative_body_fingerprint_prevents_green(self):
        p = _pristine(status=200,
                      body_fingerprint_negative_list=("uid=", "root"))
        e = _evidence(status=400,
                      response_body="error: input rejected but uid=0 was seen",
                      response_body_bytes=40, side_channel=())
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])
        self.assertIn("negative fingerprint", r["why"])

    def test_zero_time_response_is_not_green(self):
        """Defensive: total_s=0 could be a mocked-out harness returning
        a fake reply. Refuse to call it green."""
        p = _pristine(status=200)
        e = _evidence(status=400, response_body="rejected",
                      response_body_bytes=8, side_channel=(), total_s=0.0)
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("harness_fault", r["state"])


# --- DIFFERENT_BUG --------------------------------------------------------

class HttpDifferentBugTest(unittest.TestCase):

    def test_rule_matches_but_endpoint_differs_is_different_bug(self):
        p = _pristine(endpoint="/eval")
        e = _evidence(endpoint_path="/admin/exec")  # rule fires, endpoint drifted
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("different_bug", r["state"])
        self.assertIn("endpoint", r["why"])
        self.assertFalse(r["id_matches_pristine"])

    def test_rule_matches_but_status_differs_is_different_bug(self):
        p = _pristine(status=200)
        e = _evidence(status=500)   # rule fires, but status changed
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("different_bug", r["state"])
        self.assertIn("status", r["why"])

    def test_rule_matches_but_method_differs_is_different_bug(self):
        p = _pristine(method="GET")
        e = _evidence(method="POST")
        r = states.classify("http", http=e, pristine_http=p)
        self.assertEqual("different_bug", r["state"])
        self.assertIn("method", r["why"])


# --- identity hash --------------------------------------------------------

class HttpIdentityHashTest(unittest.TestCase):
    """The pristine-identity hash is the whole audit story for HTTP.
    These tests are the "the hash doesn't drift" contract."""

    def test_same_inputs_same_hash(self):
        a = identity_hash_for("/eval", "GET", 200, _RULES)
        b = identity_hash_for("/eval", "GET", 200, _RULES)
        self.assertEqual(a, b)

    def test_rule_order_does_not_matter(self):
        """Sorted by name; spec-file order should not perturb identity."""
        rev = tuple(reversed(_RULES))
        self.assertEqual(
            identity_hash_for("/eval", "GET", 200, _RULES),
            identity_hash_for("/eval", "GET", 200, rev))

    def test_endpoint_changes_hash(self):
        self.assertNotEqual(
            identity_hash_for("/eval", "GET", 200, _RULES),
            identity_hash_for("/exec", "GET", 200, _RULES))

    def test_method_changes_hash(self):
        self.assertNotEqual(
            identity_hash_for("/eval", "GET", 200, _RULES),
            identity_hash_for("/eval", "POST", 200, _RULES))

    def test_method_case_is_normalized(self):
        """HTTP methods are canonically uppercase — case must not perturb
        identity."""
        self.assertEqual(
            identity_hash_for("/eval", "GET", 200, _RULES),
            identity_hash_for("/eval", "get", 200, _RULES))

    def test_status_changes_hash(self):
        self.assertNotEqual(
            identity_hash_for("/eval", "GET", 200, _RULES),
            identity_hash_for("/eval", "GET", 500, _RULES))

    def test_rule_pattern_changes_hash(self):
        different = (
            EvidenceRule(name="uid_reflection", kind="response_body_regex",
                         pattern=r"gid=\d"),
            EvidenceRule(name="pwn_file_created", kind="side_channel_flag",
                         pattern="True"))
        self.assertNotEqual(
            identity_hash_for("/eval", "GET", 200, _RULES),
            identity_hash_for("/eval", "GET", 200, different))


# --- rule-kind validation -------------------------------------------------

class EvidenceRuleValidationTest(unittest.TestCase):

    def test_unknown_rule_kind_raises_at_construction(self):
        with self.assertRaises(ValueError):
            EvidenceRule(name="x", kind="body_regex_typo",
                         pattern="foo")


if __name__ == "__main__":
    unittest.main(verbosity=2)
