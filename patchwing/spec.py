"""Spec artifact schema — Pass 2 extension for HTTP-shape reproducers.

Every finding carries a `spec` artifact whose JSON content configures how
downstream stages talk to the target: the container image, the reproduce
command, the reproducer file set. Pass 2 adds one sibling field —
`reproducer_kind` — that dispatches reproduce's classifier between the
sanitizer path (existing ARVO-shaped findings) and the HTTP path (Pass 1's
classifier + Pass 2's provisioner).

Backward compatibility rule (the reason this module is small):
    spec.get("reproducer_kind")  absent  →  "sanitizer"

Every historical ARVO spec on disk lacks the field. Every consumer that
routed on the historical shape continues to route the same way. Only NEW
non-ARVO findings (Pass 2 provisioner output) carry `reproducer_kind="http"`
+ the `http` sub-block.

Validation is loud on shape errors and silent on absence. A spec that never
declares HTTP is untouched; a spec that DOES declare HTTP must supply the
whole sub-block, because a half-populated block would silently degrade to
the sanitizer path at reproduce and read every response as harness_fault.
"""
from __future__ import annotations

REPRODUCER_KIND_SANITIZER = "sanitizer"
REPRODUCER_KIND_HTTP = "http"
REPRODUCER_KINDS = (REPRODUCER_KIND_SANITIZER, REPRODUCER_KIND_HTTP)


class SpecError(ValueError):
    """A spec artifact is malformed. Callers translate to StageResult.fail
    with a specific outcome so the audit trail names the exact defect."""


def reproducer_kind(spec: dict | None) -> str:
    """The kind declared by a spec, or 'sanitizer' if unspecified.

    Absent is the historical default — every ARVO spec on disk hits this
    path unchanged."""
    if not spec:
        return REPRODUCER_KIND_SANITIZER
    k = spec.get("reproducer_kind", REPRODUCER_KIND_SANITIZER)
    if k not in REPRODUCER_KINDS:
        raise SpecError(
            f"spec.reproducer_kind {k!r} is not one of {REPRODUCER_KINDS}")
    return k


# ---------------------------------------------------------------------------
# Ownership boundary for the http sub-block:
#
#   Operator authors   : endpoint_path_norm, method, expected_status_red,
#                        expected_green_statuses, evidence_rules,
#                        body_fingerprint_negative_list
#   Provision authors  : url
#
# The split exists because the operator doesn't know host:port until
# provision picks a base image and stands the pod up. Two validators —
# one draft (no url), one full (url required) — enforce this at both
# ends of the pipeline. A future refactor that tries to unify them needs
# to see this note first: collapsing the two would either force the
# operator to guess host:port before provision runs (wrong ownership) or
# let provision skip writing url (silent broken spec). Neither is a
# reasonable trade for the cost of one extra function.
#
# The draft-validator ALSO rejects a url field if the operator supplies
# one — the split has to stay one-sided or `provision` will collide with
# a stale operator-authored url on the final spec write.
# ---------------------------------------------------------------------------

def validate_http_block(spec: dict, *, require_url: bool = True) -> None:
    """Enforce the http sub-block schema. Raises SpecError on any defect.

    `require_url` defaults to True — the schema reproduce reads. Provision
    sets require_url=False on its intermediate reads if it hasn't written
    the URL yet; the DRAFT-validator (see validate_http_draft_block) is
    what the operator-authored payload should go through.

    A spec that OMITS the http block passes this check silently — the
    guard against 'declares http but supplies no block' is at
    `normalize_spec`, which is the single entry point for readers that
    intend to dispatch on kind."""
    http = spec.get("http")
    if http is None:
        raise SpecError(
            "spec.reproducer_kind='http' requires a spec.http sub-block")
    if not isinstance(http, dict):
        raise SpecError(
            f"spec.http must be a dict, got {type(http).__name__}")

    required = ["method", "endpoint_path_norm",
                "expected_status_red", "evidence_rules"]
    if require_url:
        required.insert(0, "url")
    for k in required:
        if k not in http:
            raise SpecError(f"spec.http missing required field {k!r}")

    if "url" in http:
        if not isinstance(http["url"], str) or not http["url"].strip():
            raise SpecError("spec.http.url must be a non-empty string")
    if not isinstance(http["method"], str) or not http["method"].strip():
        raise SpecError("spec.http.method must be a non-empty string")
    if (not isinstance(http["endpoint_path_norm"], str)
            or not http["endpoint_path_norm"].startswith("/")):
        raise SpecError(
            "spec.http.endpoint_path_norm must be a string starting with '/'")
    if (not isinstance(http["expected_status_red"], int)
            or http["expected_status_red"] < 100
            or http["expected_status_red"] > 599):
        raise SpecError(
            "spec.http.expected_status_red must be an HTTP status int in "
            "[100, 599]")

    rules = http["evidence_rules"]
    if not isinstance(rules, list) or not rules:
        raise SpecError(
            "spec.http.evidence_rules must be a NON-EMPTY list. A classifier "
            "with no rules can never call red, which is the silent-green "
            "failure the whole classifier module exists to prevent.")

    # Delegate rule-kind validation to states.EvidenceRule so we don't drift.
    from .states import EvidenceRule
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise SpecError(
                f"spec.http.evidence_rules[{i}] must be a dict, "
                f"got {type(r).__name__}")
        for f in ("name", "kind", "pattern"):
            if f not in r:
                raise SpecError(
                    f"spec.http.evidence_rules[{i}] missing {f!r}")
            if not isinstance(r[f], str) or not r[f]:
                raise SpecError(
                    f"spec.http.evidence_rules[{i}].{f} must be a "
                    f"non-empty string")
        try:
            EvidenceRule(name=r["name"], kind=r["kind"], pattern=r["pattern"])
        except ValueError as e:
            raise SpecError(
                f"spec.http.evidence_rules[{i}]: {e}") from e

    egs = http.get("expected_green_statuses")
    if egs is not None:
        if (not isinstance(egs, list)
                or not all(isinstance(x, int) and 100 <= x <= 599 for x in egs)):
            raise SpecError(
                "spec.http.expected_green_statuses must be a list of HTTP "
                "status ints in [100, 599]")

    neg = http.get("body_fingerprint_negative_list")
    if neg is not None:
        if (not isinstance(neg, list)
                or not all(isinstance(x, str) for x in neg)):
            raise SpecError(
                "spec.http.body_fingerprint_negative_list must be a list "
                "of strings")

    # Pod-template preference — optional, string, references a template
    # by NAME. Existence is NOT checked here (pure validators don't touch
    # the DB); use validate_preferred_template_exists(spec, store) at
    # save-time. Absent = no preference = provision picks the default
    # base image (ubuntu:22.04 today). Both the operator draft AND the
    # provision-written final spec may carry this field — ownership is
    # OPERATOR-authored on this field (unlike url).
    pt = http.get("preferred_template")
    if pt is not None:
        if not isinstance(pt, str) or not pt.strip():
            raise SpecError(
                "spec.http.preferred_template must be a non-empty string "
                "(template name), or omitted")


def validate_http_draft_block(spec: dict) -> None:
    """Validate an OPERATOR-authored draft of the http sub-block.

    Two differences from validate_http_block:
      1. `url` is NOT required — provision writes it, not the operator.
      2. `url` is EXPLICITLY REJECTED if the operator supplies one.
         The ownership split has to stay one-sided (see the comment
         block above validate_http_block); allowing a stale operator-
         authored url on the draft would collide with provision's final
         write and mask which value the reproducer actually hit.

    Every other operator-authored field is validated exactly as it is
    at the full-spec boundary — no partial checks, no defer-to-later."""
    http = spec.get("http")
    if isinstance(http, dict) and "url" in http:
        raise SpecError(
            "spec.http.url is set by provision, not the operator — "
            "remove it from the draft. See patchwing/spec.py ownership "
            "boundary comment for why the split is one-sided.")
    validate_http_block(spec, require_url=False)




def validate_bypass_fields_stage_scope(spec: dict, spec_stage: str) -> None:
    """Rev-6: reproducer.origin='operator_target_toml' and target.prebuilt=True
    are INGEST-ONLY flags. Any spec authored at a later stage (e.g. provision)
    that sets them is a bypass attempt on the wall's shape-check exemption
    and MUST be rejected here.

    Called from server.spec_save and from any store.add_artifact caller
    that writes a `spec` artifact at a post-ingest stage."""
    if spec_stage == "ingest":
        return  # ingest may set these freely (that's the operator's path)
    origin = ((spec.get("reproducer") or {}).get("origin") or "").strip()
    if origin == "operator_target_toml":
        raise SpecError(
            f"spec at stage={spec_stage!r} cannot set "
            f"reproducer.origin='operator_target_toml' — that is an ingest-"
            f"only flag (Rev-6 lockdown). Provision-authored specs must "
            f"either omit reproducer.origin or set it to 'provision_materialized'.")
    if (spec.get("target") or {}).get("prebuilt"):
        raise SpecError(
            f"spec at stage={spec_stage!r} cannot set target.prebuilt=True — "
            f"that is an ingest-only flag (Rev-6 lockdown).")


def normalize_spec(spec: dict | None) -> dict:
    """Return a shallow-copy spec with reproducer_kind explicitly set and,
    for HTTP kind, the http block validated.

    Callers that intend to DISPATCH on reproducer_kind should go through
    this function — validation happens exactly once, at the boundary,
    instead of every stage re-implementing the same checks."""
    if spec is None:
        return {"reproducer_kind": REPRODUCER_KIND_SANITIZER}
    if not isinstance(spec, dict):
        raise SpecError(
            f"spec must be a dict, got {type(spec).__name__}")
    out = dict(spec)
    kind = reproducer_kind(out)
    out["reproducer_kind"] = kind
    if kind == REPRODUCER_KIND_HTTP:
        validate_http_block(out)
    return out


def validate_preferred_template_exists(spec: dict, store) -> None:
    """Runtime check that spec.http.preferred_template, if set, refers
    to a template that actually exists in pod_templates. Called by save
    paths (draft_spec_save, provision spec writer) so a stale name is
    rejected AT SAVE, not silently at provision-attach time.

    Non-http specs are a no-op. Absent preferred_template is a no-op.
    A referenced-but-missing template raises SpecError.

    Kept OUT of validate_http_block because pure validators must not
    touch the DB — that would make schema tests need a store fixture
    for something the schema itself doesn't guarantee. Two functions,
    two concerns: shape vs presence."""
    if reproducer_kind(spec) != REPRODUCER_KIND_HTTP:
        return
    pt = ((spec.get("http") or {}).get("preferred_template") or "").strip()
    if not pt:
        return
    if store.get_template(pt) is None:
        raise SpecError(
            f"spec.http.preferred_template refers to {pt!r} but no "
            f"template with that name exists in pod_templates — pick "
            f"one from /templates or clear the field")


def http_pristine_from_spec(spec: dict):
    """Build a HttpPristine from a validated http spec.

    Convenience helper — the provision stage and reproduce stage both need
    to build the pristine from the same source of truth. Duplicating the
    reconstruction pattern in two call sites is the shape of bugs where
    provision writes one identity hash and reproduce recomputes a
    different one.

    Returns states.HttpPristine ready to hand to states.classify(kind='http',
    pristine_http=..., http=...) or to a reproducer_lock writer."""
    from .states import EvidenceRule, HttpPristine, identity_hash_for
    kind = reproducer_kind(spec)
    if kind != REPRODUCER_KIND_HTTP:
        raise SpecError(
            f"http_pristine_from_spec called with reproducer_kind={kind!r}")
    validate_http_block(spec)
    http = spec["http"]
    rules = tuple(
        EvidenceRule(name=r["name"], kind=r["kind"], pattern=r["pattern"])
        for r in http["evidence_rules"])
    egs = http.get("expected_green_statuses")
    egs_frozen = frozenset(egs) if egs is not None else None
    neg = tuple(http.get("body_fingerprint_negative_list", ()) or ())
    status = int(http["expected_status_red"])
    endpoint = http["endpoint_path_norm"]
    method = http["method"]
    return HttpPristine(
        endpoint_path_norm=endpoint,
        method=method,
        status=status,
        evidence_rules=rules,
        identity_hash=identity_hash_for(endpoint, method, status, rules),
        expected_green_statuses=egs_frozen,
        body_fingerprint_negative_list=neg,
    )
