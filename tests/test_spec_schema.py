"""Spec schema — Pass 2 extension for reproducer_kind='http'.

Tests the validation surface for the new http sub-block, and confirms that
every historical (absent-key) spec passes through unchanged as
reproducer_kind='sanitizer'. The 'silently degrades to the sanitizer path'
failure mode gets its own test — that's the mode that would let a bad
http spec read every response as harness_fault without complaint.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import spec as spec_mod                     # noqa: E402
from patchwing.states import (                             # noqa: E402
    HttpPristine, identity_hash_for)


def _valid_http_spec() -> dict:
    return {
        "reproducer_kind": "http",
        "target": {"image": "openjdk:8", "mode": "in-image", "root": "/src"},
        "commands": {"reproduce": "curl -sf http://target:8080/x"},
        "http": {
            "url": "http://target:8080/eval",
            "method": "GET",
            "endpoint_path_norm": "/eval",
            "expected_status_red": 200,
            "expected_green_statuses": [400, 403],
            "evidence_rules": [
                {"name": "uid_reflection",
                 "kind": "response_body_regex",
                 "pattern": r"uid=\d+\("},
                {"name": "pwn_file_created",
                 "kind": "side_channel_flag",
                 "pattern": "True"},
            ],
            "body_fingerprint_negative_list": ["uid=0(root)"],
        },
    }


# --- reproducer_kind ------------------------------------------------------

class ReproducerKindTest(unittest.TestCase):

    def test_absent_key_defaults_to_sanitizer(self):
        """Every ARVO spec on disk has no reproducer_kind key. They must
        pass through as sanitizer — the whole backward-compat rule."""
        self.assertEqual("sanitizer", spec_mod.reproducer_kind({}))
        self.assertEqual(
            "sanitizer",
            spec_mod.reproducer_kind({"target": {"image": "gcr.io/oss-fuzz"}}))

    def test_empty_or_none_spec_defaults_to_sanitizer(self):
        self.assertEqual("sanitizer", spec_mod.reproducer_kind(None))
        self.assertEqual("sanitizer", spec_mod.reproducer_kind({}))

    def test_http_kind_returned_when_set(self):
        self.assertEqual("http", spec_mod.reproducer_kind(_valid_http_spec()))

    def test_unknown_kind_raises_specerror(self):
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.reproducer_kind({"reproducer_kind": "grpc"})


# --- validate_http_block --------------------------------------------------

class ValidateHttpBlockTest(unittest.TestCase):

    def test_valid_http_block_passes(self):
        spec_mod.validate_http_block(_valid_http_spec())

    def test_missing_http_block_raises(self):
        with self.assertRaisesRegex(spec_mod.SpecError, "sub-block"):
            spec_mod.validate_http_block({"reproducer_kind": "http"})

    def test_http_not_a_dict_raises(self):
        with self.assertRaisesRegex(spec_mod.SpecError, "must be a dict"):
            spec_mod.validate_http_block(
                {"reproducer_kind": "http", "http": "nope"})

    def test_missing_required_field_raises_for_each(self):
        base = _valid_http_spec()
        for f in ("url", "method", "endpoint_path_norm",
                  "expected_status_red", "evidence_rules"):
            s = {k: v for k, v in base.items()}
            s["http"] = {k: v for k, v in base["http"].items() if k != f}
            with self.assertRaisesRegex(spec_mod.SpecError,
                                        f"missing required field '{f}'"):
                spec_mod.validate_http_block(s)

    def test_empty_url_raises(self):
        s = _valid_http_spec(); s["http"]["url"] = ""
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.validate_http_block(s)

    def test_endpoint_path_norm_must_start_with_slash(self):
        s = _valid_http_spec(); s["http"]["endpoint_path_norm"] = "eval"
        with self.assertRaisesRegex(spec_mod.SpecError, "must be a string starting with '/'"):
            spec_mod.validate_http_block(s)

    def test_expected_status_red_out_of_range_raises(self):
        for bad in (0, 99, 600, 999, "200"):
            s = _valid_http_spec(); s["http"]["expected_status_red"] = bad
            with self.assertRaises(spec_mod.SpecError):
                spec_mod.validate_http_block(s)

    def test_empty_evidence_rules_raises(self):
        """A classifier with no rules can never call red — silent-green.
        Refuse loud rather than silently degrade."""
        s = _valid_http_spec(); s["http"]["evidence_rules"] = []
        with self.assertRaisesRegex(spec_mod.SpecError,
                                    "silent-green"):
            spec_mod.validate_http_block(s)

    def test_evidence_rule_missing_field_raises(self):
        for f in ("name", "kind", "pattern"):
            s = _valid_http_spec()
            r = dict(s["http"]["evidence_rules"][0])
            r.pop(f)
            s["http"]["evidence_rules"] = [r]
            with self.assertRaisesRegex(spec_mod.SpecError,
                                        f"missing '{f}'"):
                spec_mod.validate_http_block(s)

    def test_evidence_rule_empty_string_raises(self):
        s = _valid_http_spec()
        s["http"]["evidence_rules"][0]["name"] = ""
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.validate_http_block(s)

    def test_evidence_rule_bad_kind_delegates_to_evidence_rule(self):
        """Rule-kind validation MUST route through states.EvidenceRule so
        the two files don't drift."""
        s = _valid_http_spec()
        s["http"]["evidence_rules"][0]["kind"] = "body_regex_typo"
        with self.assertRaisesRegex(spec_mod.SpecError,
                                    "unknown EvidenceRule.kind"):
            spec_mod.validate_http_block(s)

    def test_expected_green_statuses_may_be_omitted(self):
        s = _valid_http_spec()
        del s["http"]["expected_green_statuses"]
        spec_mod.validate_http_block(s)

    def test_expected_green_statuses_bad_type_raises(self):
        s = _valid_http_spec()
        s["http"]["expected_green_statuses"] = "400,403"
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.validate_http_block(s)
        s["http"]["expected_green_statuses"] = [400, "403"]
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.validate_http_block(s)

    def test_body_fingerprint_negative_list_may_be_omitted(self):
        s = _valid_http_spec()
        del s["http"]["body_fingerprint_negative_list"]
        spec_mod.validate_http_block(s)

    def test_body_fingerprint_negative_list_bad_type_raises(self):
        s = _valid_http_spec()
        s["http"]["body_fingerprint_negative_list"] = "uid=root"
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.validate_http_block(s)


# --- normalize_spec -------------------------------------------------------

class NormalizeSpecTest(unittest.TestCase):

    def test_none_spec_normalizes_to_sanitizer(self):
        self.assertEqual({"reproducer_kind": "sanitizer"},
                         spec_mod.normalize_spec(None))

    def test_empty_spec_normalizes_to_sanitizer(self):
        n = spec_mod.normalize_spec({})
        self.assertEqual("sanitizer", n["reproducer_kind"])

    def test_arvo_shaped_spec_normalizes_to_sanitizer(self):
        """The BACKWARD COMPAT test. A historical spec must pass through
        unchanged aside from getting reproducer_kind='sanitizer' added."""
        arvo = {"target": {"image": "gcr.io/oss-fuzz-base/x", "mode": "in-image"},
                "commands": {"reproduce": "arvo run"},
                "reproducer": {"files": ["crash-abc"]}}
        n = spec_mod.normalize_spec(arvo)
        self.assertEqual("sanitizer", n["reproducer_kind"])
        self.assertEqual(arvo["target"], n["target"])
        self.assertEqual(arvo["commands"], n["commands"])
        self.assertEqual(arvo["reproducer"], n["reproducer"])

    def test_valid_http_spec_passes_through(self):
        s = _valid_http_spec()
        n = spec_mod.normalize_spec(s)
        self.assertEqual("http", n["reproducer_kind"])
        self.assertEqual(s["http"], n["http"])

    def test_bad_http_spec_raises_at_normalize(self):
        """Silent-degrade guard: a spec that claims http but supplies a
        malformed http block must NOT fall through to sanitizer."""
        s = _valid_http_spec()
        s["http"]["evidence_rules"] = []
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.normalize_spec(s)

    def test_non_dict_spec_raises(self):
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.normalize_spec("not a dict")

    def test_normalize_is_a_shallow_copy(self):
        """Callers should not observe mutation of the input dict."""
        s = _valid_http_spec()
        s_copy = dict(s)
        spec_mod.normalize_spec(s)
        self.assertEqual(s_copy, s)


# --- http_pristine_from_spec ---------------------------------------------

class HttpPristineFromSpecTest(unittest.TestCase):
    """The provision + reproduce stages both reconstruct the pristine from
    the spec. They MUST agree byte-for-byte on the identity hash — a drift
    here is the shape of bugs where provision writes one hash and reproduce
    recomputes a different one."""

    def test_builds_correct_httppristine(self):
        p = spec_mod.http_pristine_from_spec(_valid_http_spec())
        self.assertIsInstance(p, HttpPristine)
        self.assertEqual("/eval", p.endpoint_path_norm)
        self.assertEqual("GET", p.method)
        self.assertEqual(200, p.status)
        self.assertEqual(2, len(p.evidence_rules))
        self.assertEqual(frozenset({400, 403}), p.expected_green_statuses)
        self.assertEqual(("uid=0(root)",), p.body_fingerprint_negative_list)

    def test_identity_hash_matches_direct_call(self):
        s = _valid_http_spec()
        p = spec_mod.http_pristine_from_spec(s)
        h = s["http"]
        from patchwing.states import EvidenceRule
        rules = tuple(
            EvidenceRule(name=r["name"], kind=r["kind"], pattern=r["pattern"])
            for r in h["evidence_rules"])
        expected = identity_hash_for(
            h["endpoint_path_norm"], h["method"],
            int(h["expected_status_red"]), rules)
        self.assertEqual(expected, p.identity_hash)

    def test_raises_on_sanitizer_spec(self):
        with self.assertRaisesRegex(spec_mod.SpecError,
                                    "called with reproducer_kind='sanitizer'"):
            spec_mod.http_pristine_from_spec({})

    def test_expected_green_statuses_absent_becomes_none(self):
        s = _valid_http_spec()
        del s["http"]["expected_green_statuses"]
        p = spec_mod.http_pristine_from_spec(s)
        self.assertIsNone(p.expected_green_statuses)

    def test_body_fingerprint_negative_list_absent_becomes_empty(self):
        s = _valid_http_spec()
        del s["http"]["body_fingerprint_negative_list"]
        p = spec_mod.http_pristine_from_spec(s)
        self.assertEqual((), p.body_fingerprint_negative_list)


# --- draft validator (ownership boundary) --------------------------------

class ValidateHttpDraftBlockTest(unittest.TestCase):
    """The operator-authored draft omits url (provision writes it). The
    draft validator has to (a) not require url, (b) actively reject url
    if the operator supplies one — the split must stay one-sided or a
    stale operator-authored url will collide with provision's write."""

    def _draft(self) -> dict:
        s = _valid_http_spec()
        del s["http"]["url"]                # operator doesn't author url
        return s

    def test_draft_validator_accepts_no_url(self):
        spec_mod.validate_http_draft_block(self._draft())

    def test_draft_validator_rejects_url_field(self):
        """The re-merge guard. If the operator supplies url, refuse — the
        ownership boundary must stay one-sided."""
        s = self._draft()
        s["http"]["url"] = "http://target:8080/eval"
        with self.assertRaisesRegex(spec_mod.SpecError,
                                    "url is set by provision"):
            spec_mod.validate_http_draft_block(s)

    def test_draft_validator_shares_all_other_field_checks(self):
        """The three failure modes the full validator catches must also
        be caught by the draft validator — no partial checks."""
        # missing evidence_rules
        s = self._draft(); del s["http"]["evidence_rules"]
        with self.assertRaisesRegex(spec_mod.SpecError,
                                    "missing required field 'evidence_rules'"):
            spec_mod.validate_http_draft_block(s)
        # empty evidence_rules
        s = self._draft(); s["http"]["evidence_rules"] = []
        with self.assertRaisesRegex(spec_mod.SpecError, "silent-green"):
            spec_mod.validate_http_draft_block(s)
        # bad rule kind
        s = self._draft()
        s["http"]["evidence_rules"][0]["kind"] = "body_regex_typo"
        with self.assertRaisesRegex(spec_mod.SpecError,
                                    "unknown EvidenceRule.kind"):
            spec_mod.validate_http_draft_block(s)


class ValidateHttpBlockRequireUrlKwargTest(unittest.TestCase):
    """The `require_url` kwarg is the internal knob the draft validator
    uses. Guard against a future refactor that changes the default."""

    def test_default_requires_url(self):
        s = _valid_http_spec(); del s["http"]["url"]
        with self.assertRaisesRegex(spec_mod.SpecError,
                                    "missing required field 'url'"):
            spec_mod.validate_http_block(s)

    def test_require_url_false_accepts_no_url(self):
        s = _valid_http_spec(); del s["http"]["url"]
        spec_mod.validate_http_block(s, require_url=False)

    def test_require_url_false_still_validates_present_url(self):
        s = _valid_http_spec(); s["http"]["url"] = ""
        with self.assertRaises(spec_mod.SpecError):
            spec_mod.validate_http_block(s, require_url=False)


# --- preferred_template (Pass 3 Step 5) -----------------------------------

class PreferredTemplateShapeTest(unittest.TestCase):
    """preferred_template field on the http block. Optional, string,
    references a template by NAME. Shape validation only — existence
    is a separate function (validate_preferred_template_exists)."""

    def _http_with(self, val):
        s = _valid_http_spec()
        s["http"]["preferred_template"] = val
        return s

    def test_absent_passes(self):
        spec_mod.validate_http_block(_valid_http_spec())

    def test_valid_string_passes(self):
        spec_mod.validate_http_block(self._http_with("tomcat-jdk8"))

    def test_none_treated_as_absent(self):
        spec_mod.validate_http_block(self._http_with(None))

    def test_empty_string_raises(self):
        with self.assertRaisesRegex(spec_mod.SpecError, "non-empty string"):
            spec_mod.validate_http_block(self._http_with(""))

    def test_whitespace_only_raises(self):
        with self.assertRaisesRegex(spec_mod.SpecError, "non-empty string"):
            spec_mod.validate_http_block(self._http_with("   "))

    def test_non_string_raises(self):
        for bad in (123, ["tomcat"], {"name": "x"}, True):
            with self.assertRaises(spec_mod.SpecError):
                spec_mod.validate_http_block(self._http_with(bad))

    def test_draft_validator_accepts_preferred_template(self):
        """Operator authors preferred_template; the draft validator
        must accept it (unlike url, which is provision-only)."""
        s = self._http_with("tomcat-jdk8")
        del s["http"]["url"]           # operator draft has no url
        spec_mod.validate_http_draft_block(s)


class ValidatePreferredTemplateExistsTest(unittest.TestCase):
    """Runtime existence check — needs a Store. Rejects a name that
    doesn't correspond to any pod_templates row."""

    def _mk_store(self):
        import tempfile
        from patchwing.store import Store
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        return Store(tmp.name), tmp.name

    def _seed(self, store, name="tomcat-jdk8"):
        from patchwing import templates as tpl_mod
        store.add_template(
            name=name, description=f"{name}", base_image="ubuntu:22.04",
            image_tag=tpl_mod.image_tag_for(name),
            recipe_json="[]", recipe_turn_count=0,
            verification_cmd="echo hi", verification_expect=".",
            builder_version=tpl_mod.BUILDER_VERSION_CURRENT)

    def _rm(self, p):
        try: os.unlink(p)
        except OSError: pass

    def test_no_preferred_template_is_noop(self):
        s, p = self._mk_store()
        try:
            spec_mod.validate_preferred_template_exists(
                _valid_http_spec(), s)   # must not raise
        finally:
            s.close(); self._rm(p)

    def test_sanitizer_kind_is_noop(self):
        """Non-http specs never carry preferred_template — check is a
        no-op regardless of what's in the dict."""
        s, p = self._mk_store()
        try:
            spec_mod.validate_preferred_template_exists({}, s)
            spec_mod.validate_preferred_template_exists(
                {"reproducer_kind": "sanitizer"}, s)
        finally:
            s.close(); self._rm(p)

    def test_existing_template_passes(self):
        s, p = self._mk_store()
        try:
            self._seed(s, "tomcat-jdk8")
            spec = _valid_http_spec()
            spec["http"]["preferred_template"] = "tomcat-jdk8"
            spec_mod.validate_preferred_template_exists(spec, s)
        finally:
            s.close(); self._rm(p)

    def test_missing_template_raises(self):
        s, p = self._mk_store()
        try:
            spec = _valid_http_spec()
            spec["http"]["preferred_template"] = "does-not-exist"
            with self.assertRaisesRegex(spec_mod.SpecError,
                                        "does-not-exist"):
                spec_mod.validate_preferred_template_exists(spec, s)
        finally:
            s.close(); self._rm(p)

    def test_wrong_template_name_raises_even_if_others_present(self):
        s, p = self._mk_store()
        try:
            self._seed(s, "tomcat-jdk8")
            self._seed(s, "apache-httpd-24")
            spec = _valid_http_spec()
            spec["http"]["preferred_template"] = "nodejs-42-nope"
            with self.assertRaises(spec_mod.SpecError):
                spec_mod.validate_preferred_template_exists(spec, s)
        finally:
            s.close(); self._rm(p)


# --- BACKWARD-COMPAT — Pass 3 Step 5 requirement ------------------------

class BackwardCompatAgainstARVOSpecsTest(unittest.TestCase):
    """Explicit check: adding preferred_template to the schema must not
    break existing ARVO specs (which have no http block, no reproducer_
    kind, no preferred_template). Regression guard against a future
    refactor that would make the new field somehow mandatory."""

    def _arvo_spec(self) -> dict:
        """Approximates the shape ARVO ingest writes to store (see
        cli.py:91)."""
        return {
            "target": {
                "image": "gcr.io/oss-fuzz-base/arvo:1076-vul",
                "mode": "in-image",
                "root": "/src",
                "prebuilt": True,
                "fix_writer_view": "window",
            },
            "commands": {
                "reproduce": "arvo run",
                "build": "arvo build",
            },
            "reproducer": {
                "files": ["fuzz-target/crash-abc123"],
            },
        }

    def test_arvo_spec_normalizes_as_sanitizer(self):
        n = spec_mod.normalize_spec(self._arvo_spec())
        self.assertEqual("sanitizer", n["reproducer_kind"])
        # Rest of the spec passed through verbatim
        self.assertEqual("gcr.io/oss-fuzz-base/arvo:1076-vul",
                         n["target"]["image"])
        self.assertEqual("arvo run", n["commands"]["reproduce"])

    def test_arvo_spec_has_no_preferred_template(self):
        """Sanity: ARVO specs simply don't have this field. Confirm the
        validators don't invent one."""
        n = spec_mod.normalize_spec(self._arvo_spec())
        self.assertNotIn("http", n)
        # No http block to have a preferred_template on
        self.assertNotIn("preferred_template",
                         (n.get("http") or {}))

    def test_arvo_spec_existence_check_is_noop(self):
        """Sanity: the store-dependent check does nothing on ARVO specs
        even if no store is provided (we pass None safely)."""
        # A stub that would explode if called
        stub = object()
        spec_mod.validate_preferred_template_exists(
            self._arvo_spec(), stub)


if __name__ == "__main__":
    unittest.main(verbosity=2)
