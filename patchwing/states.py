"""§6b′ — FOUR states, never two.

The whole reason this module exists: **1237 exits 1.** That is the least
distinctive non-zero code there is. A missing mount returns 1. A shell error
returns 1. A container that never started returns 1. Under a plain `non-zero =
red` test, every malfunction reads as "the bug reproduced" — and at the rollback
leg the assertion *is* "red again", so any malfunction satisfies it. That is a
check that cannot fail, which is not a check.

So a run is never classified by exit code alone. Three signals are read together:

    exit code   +   sanitizer marker   +   DEDUP_TOKEN identity

and they resolve to one of four states. `different_bug` and `harness_fault` are
neither red nor green and **must never fold into either**. Folding them is the
(a)/(b) collapse this project keeps finding one layer up: absence wearing
failure's face.

The marker regex is deliberately sanitizer-agnostic:

    (ERROR|SUMMARY): (Address|Memory|UndefinedBehavior|Thread)Sanitizer

**Leak is dropped on purpose.** LeakSanitizer fires at process exit on leaks
that have nothing to do with the bug under test, so including it would
manufacture false reds — and a false red at the rollback leg is exactly the
malfunction that would satisfy "red again" while proving nothing.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

# --- the four states -------------------------------------------------------
# Decision table:
#   marker present + DEDUP_TOKEN matches pristine    -> CONFIRMED_RED
#   marker present + DEDUP_TOKEN does not match      -> DIFFERENT_BUG
#   no marker      + exit 0                          -> CONFIRMED_GREEN
#   no marker      + exit non-zero                   -> HARNESS_FAULT
#
# Exit code is SECONDARY. It is consulted only when there is no marker. MSan
# is regularly configured with `abort_on_error=0` — that is the supported,
# documented mode, and libFuzzer exits 0 after it. Treating exit-0-with-marker
# as "the exit code and the output disagree" mislabels every MSan-reported red
# in the corpus as a harness fault, and corrupts every iteration signal.
CONFIRMED_RED = "confirmed_red"      # marker + token matches pristine
CONFIRMED_GREEN = "confirmed_green"  # clean exit + no marker
DIFFERENT_BUG = "different_bug"      # marker present + token MISMATCH (or missing)
HARNESS_FAULT = "harness_fault"      # no marker + non-zero exit (or timeout)

ALL_STATES = frozenset({CONFIRMED_RED, CONFIRMED_GREEN, DIFFERENT_BUG,
                        HARNESS_FAULT})

MARKER_RE = re.compile(
    r"(ERROR|SUMMARY): (Address|Memory|UndefinedBehavior|Thread)Sanitizer")

# ClusterFuzz/ARVO emit this; it is the crash identity, not just its location.
_DEDUP_RE = re.compile(r"DEDUP_TOKEN:\s*(\S+)")

# Fallback identity when a corpus emits no DEDUP_TOKEN: the SUMMARY line's
# function+file. Weaker, and recorded as weaker — never silently substituted.
_SUMMARY_RE = re.compile(
    r"SUMMARY:\s+\w+Sanitizer:\s+\S+\s+([^\s]+)\s+in\s+(\S+)")


def marker(output: str) -> str:
    """The matched sanitizer marker, or "" if none. Presence is the signal."""
    m = MARKER_RE.search(output or "")
    return m.group(0) if m else ""


def dedup_token(output: str) -> str:
    """The crash identity from the reproducer output, or ""."""
    m = _DEDUP_RE.search(output or "")
    if m:
        return m.group(1)
    m = _SUMMARY_RE.search(output or "")
    if m:
        return f"summary:{m.group(2)}@{m.group(1)}"
    return ""


SUPPORTED_KINDS = ("sanitizer", "http")


def classify(kind: str, *,
             returncode: int | None = None,
             output: str | None = None,
             pristine_token: str = "",
             timed_out: bool = False,
             http=None,
             rules=None,
             pristine_http=None) -> dict:
    """Dispatched classifier — routes to a kind-specific implementation.

    `kind` is REQUIRED and has no default. Every caller must state which
    input shape it is reading. This is deliberate: silently defaulting to
    "sanitizer" would let a new HTTP-shape reproducer slip through the
    sanitizer path and read "harness_fault" on every reply (no marker,
    non-zero-ish exit) — a false green from the wrong dispatch. Explicit
    opt-in prevents that whole class of failure.

    Kinds:
      "sanitizer" — reads (returncode, output) against a sanitizer marker
                    regex + DEDUP_TOKEN identity. This is the original
                    classifier, unchanged; every existing caller passes
                    kind="sanitizer" explicitly.
      "http"      — reads an HttpEvidence object against a set of named
                    EvidenceRule signatures + an HttpPristine identity
                    hash. Added in the HTTP-classifier design (see
                    docs/http-classifier-design.md).

    The returned dict is a superset. Every reading carries state / why /
    kind. Kind-specific fields let auditors reconstruct what was observed.
    """
    if kind == "sanitizer":
        if returncode is None or output is None:
            raise TypeError(
                "classify(kind='sanitizer', ...) requires returncode= and "
                "output= keyword arguments")
        return _classify_sanitizer(returncode, output, pristine_token,
                                   timed_out)
    if kind == "http":
        if http is None:
            raise TypeError(
                "classify(kind='http', ...) requires http= (HttpEvidence)")
        return _classify_http(http, pristine_http, rules=rules)
    raise ValueError(
        f"unknown classifier kind: {kind!r} (supported: {SUPPORTED_KINDS})")


def _classify_sanitizer(returncode: int, output: str, pristine_token: str,
                        timed_out: bool) -> dict:
    """Read one sanitizer execution into exactly one of the four states.

    `pristine_token` is the token recorded when the bug was FIRST reproduced, on
    unpatched code. Comparing against it is what separates "the bug we are
    tracking" from "a crash". Without that comparison, any crash anywhere counts
    as the bug, and a patch that swaps one overflow for another reads as red.

    Returns a dict rather than a bare string so every leg records what it SAW,
    not only what it concluded. A conclusion without its inputs cannot be audited.
    """
    out = output or ""
    seen_marker = marker(out)
    token = dedup_token(out)

    # Decision table (see docstring). Marker + token identity are primary; exit
    # code is secondary and consulted only when there is no marker.
    #
    # The prior code called `harness_fault` on "marker present AND exit == 0"
    # on the theory that "the exit code and the output disagree". That reasoning
    # was wrong for the majority case: MSan is configured in this corpus with
    # `abort_on_error=0`, which is the SUPPORTED, DOCUMENTED way to report and
    # continue. libFuzzer then exits 0. That is a real red being labeled
    # "harness broke", which corrupts the iteration signal — every "fix
    # didn't work" result over MSan was reading as "we don't know if the fix
    # worked". Exit code is not the arbiter; the sanitizer report is.
    if timed_out:
        # Absence, not a reading. The clock ran out; nothing was demonstrated.
        state, why = HARNESS_FAULT, "execution timed out — nothing was demonstrated"
    elif seen_marker:
        if pristine_token and token and token == pristine_token:
            state, why = (CONFIRMED_RED,
                          f"sanitizer marker present, DEDUP_TOKEN matches the "
                          f"pristine reproducer (exit {returncode})")
        elif pristine_token and token and token != pristine_token:
            state, why = (DIFFERENT_BUG,
                          f"sanitizer fired but the crash identity differs from "
                          f"the pristine reproducer ({token} != {pristine_token})")
        elif pristine_token and not token:
            # Marker without a comparable identity — this cannot be trusted as
            # the tracked bug. Do not fold into red; different_bug is honest.
            state, why = (DIFFERENT_BUG,
                          "sanitizer fired but the output carries no crash "
                          "identity to match against the pristine token — "
                          "unidentifiable")
        else:
            # No pristine to compare against (e.g. the very first reproduce
            # BEFORE the wall is frozen). Any sanitizer marker with an
            # extractable token is a red reading — this is how the pristine
            # token gets set in the first place.
            state, why = (CONFIRMED_RED,
                          f"sanitizer marker present (exit {returncode}); "
                          f"no pristine yet — this reading establishes it")
    else:
        if returncode == 0:
            state, why = CONFIRMED_GREEN, "clean exit, no sanitizer marker"
        else:
            # THE 1237 CASE. Exit 1 with no marker is a harness fault, not the
            # bug. The sanitizer never fired, so nothing demonstrates the
            # vulnerability; the non-zero exit could be a shell error, a
            # missing mount, or a container that died before reaching main.
            state, why = (HARNESS_FAULT,
                          f"exit {returncode} with no sanitizer marker — "
                          f"nothing demonstrates the vulnerability, so this "
                          f"is the harness failing, not the bug reproducing")

    return {
        "state": state,
        "why": why,
        "kind": "sanitizer",
        "returncode": returncode,
        "timed_out": timed_out,
        "marker": seen_marker or "(none)",
        "marker_present": bool(seen_marker),
        "dedup_token": token or "(none)",
        "pristine_token": pristine_token or "(none)",
        "token_matches_pristine": bool(pristine_token and token
                                       and token == pristine_token),
    }


# --- HTTP classifier -------------------------------------------------------
# Sibling of the sanitizer path. Design: docs/http-classifier-design.md.
#
# The whole trust story of the provision line: a caller that thinks it saw
# a "red" HTTP reading must have seen EVIDENCE — a named regex match in the
# response body/headers OR a named side-channel observation. A 200 response
# with a body that doesn't match any rule is NOT red. "Curl didn't error"
# is NOT red. That distinction is why this module exists as a router.

EVIDENCE_RULE_KINDS = (
    "response_body_regex",
    "response_header_regex",
    "side_channel_flag",
    "side_channel_regex",
)

# Transport-layer failures that mean "the target never responded". Any of
# these → HARNESS_FAULT, never GREEN. Silence is not proof of a fix.
_HTTP_HARNESS_TRANSPORT_ERRORS = frozenset({
    "connection_refused",
    "dns_failure",
    "tls_error",
    "connection_reset",
    "timeout_before_first_byte",
    "container_never_listened",
})


@dataclass(frozen=True)
class EvidenceRule:
    """One named signal the classifier looks for. Named (not raw regex-in-
    output) so the audit trail records "matched rule ognl_id_reflection"
    instead of a stack of unnamed regexes — same reason ASan's SUMMARY:
    lines are named markers, not raw stack frames."""
    name: str
    kind: str          # one of EVIDENCE_RULE_KINDS
    pattern: str       # regex source for *_regex kinds; verbatim value for _flag

    def __post_init__(self):
        if self.kind not in EVIDENCE_RULE_KINDS:
            raise ValueError(
                f"unknown EvidenceRule.kind {self.kind!r}; "
                f"supported: {EVIDENCE_RULE_KINDS}")


@dataclass(frozen=True)
class HttpEvidence:
    """What the reproducer captured from ONE HTTP exchange. Frozen because
    it represents an observation; mutating it after classification would
    corrupt the audit trail. See docs/http-classifier-design.md §2."""
    method: str
    endpoint_path: str
    request_headers: tuple = ()          # ordered ((name, value), ...)
    request_body_sha256: str = ""        # hash only — never raw payload
    status: int = 0                      # 0 iff no response bytes received
    response_headers: tuple = ()         # lowercased names, verbatim values
    response_body: str = ""              # UTF-8 decoded; truncate at 32KB
    response_body_bytes: int = 0
    time_to_first_byte_s: Optional[float] = None
    total_s: float = 0.0
    transport_error: str = ""            # "" iff status != 0
    transport_detail: str = ""
    side_channel: tuple = ()             # ordered ((name, value), ...)


@dataclass(frozen=True)
class HttpPristine:
    """What the wall froze on unpatched code. Comparing an observed reading
    against this is what turns "a rule fired" into "the pristine bug fired
    vs something else fired at the same endpoint". See §3."""
    endpoint_path_norm: str
    method: str
    status: int
    evidence_rules: tuple                # tuple[EvidenceRule, ...]
    identity_hash: str                   # sha256 hex; from identity_hash_for()
    expected_green_statuses: Optional[frozenset] = None
    body_fingerprint_negative_list: tuple = ()


# ASCII separators used inside the identity hash. Chosen because they
# cannot appear in a normalized URL path, a method name, or a rule name —
# so no ambiguity when we join fields for hashing.
_HTTP_ID_UNIT_SEP = "\x1f"       # between top-level fields
_HTTP_ID_RECORD_SEP = "\x1e"     # between rules
_HTTP_ID_GROUP_SEP = "\x1d"      # within a rule




# Rev-2 verdict_config freeze helpers. Reproducer_lock stores a serialized
# form of what _classify_http reads at verify; the current spec is not
# trusted at verify time. Round-trip MUST cover every field _classify_http
# reads (evidence_rules, identity_hash, endpoint_path_norm, method, status,
# expected_green_statuses, body_fingerprint_negative_list).

def serialize_pristine_http(http_block: dict, observed_status: int,
                             ev_hits: list = None) -> dict:
    """Extract the verdict-determining slice of spec.http into a plain
    JSON-serializable dict. Called at first reproduce (CONFIRMED_RED)
    to build reproducer_lock.verdict_config.http."""
    rules_serialized = []
    for r in (http_block.get("evidence_rules") or []):
        rules_serialized.append({
            "name": r.get("name", ""),
            "kind": r.get("kind", ""),
            "pattern": r.get("pattern", ""),
        })
    endpoint_path = http_block.get("endpoint_path_norm", "")
    method = http_block.get("method", "")
    egs = http_block.get("expected_green_statuses")
    egs_list = list(egs) if egs is not None else None
    neg = http_block.get("body_fingerprint_negative_list") or []
    # Build EvidenceRule tuple to compute identity_hash the same way
    # _classify_http does.
    rules_objs = tuple(EvidenceRule(name=r["name"], kind=r["kind"],
                                     pattern=r["pattern"])
                       for r in rules_serialized)
    identity = identity_hash_for(endpoint_path, method, observed_status,
                                  rules_objs)
    return {
        "kind": "http",
        "endpoint_path_norm": endpoint_path,
        "method": method,
        "status": observed_status,
        "expected_green_statuses": egs_list,
        "body_fingerprint_negative_list": list(neg),
        "identity_hash": identity,
        "evidence_rules": rules_serialized,
    }


def reconstruct_pristine_http(verdict_config: dict) -> "HttpPristine":
    """Rebuild HttpPristine from serialized verdict_config. Round-trip
    contract: every field _classify_http reads from pristine_http must be
    present here. Raises ValueError on any missing field."""
    if not isinstance(verdict_config, dict):
        raise ValueError("verdict_config must be a dict")
    required = ("endpoint_path_norm", "method", "status", "identity_hash",
                "evidence_rules")
    for k in required:
        if k not in verdict_config:
            raise ValueError(
                f"verdict_config missing required field {k!r} — cannot "
                f"reconstruct HttpPristine for verify")
    rules = tuple(EvidenceRule(name=r["name"], kind=r["kind"],
                                pattern=r["pattern"])
                  for r in verdict_config["evidence_rules"])
    egs = verdict_config.get("expected_green_statuses")
    egs_fs = frozenset(egs) if egs is not None else None
    neg = tuple(verdict_config.get("body_fingerprint_negative_list") or ())
    return HttpPristine(
        endpoint_path_norm=verdict_config["endpoint_path_norm"],
        method=verdict_config["method"],
        status=int(verdict_config["status"]),
        evidence_rules=rules,
        identity_hash=verdict_config["identity_hash"],
        expected_green_statuses=egs_fs,
        body_fingerprint_negative_list=neg,
    )


def verdict_config_sha256(verdict_config: dict) -> str:
    """Canonical JSON sha256 of the verdict_config slice, used for drift
    detection at verify entry."""
    import hashlib, json
    canonical = json.dumps(verdict_config, sort_keys=True,
                            separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
def identity_hash_for(endpoint_path_norm: str, method: str, status: int,
                      evidence_rules) -> str:
    """Compute the pristine-identity SHA-256 for an HTTP reading. Sorted
    by rule name so spec-file ordering does not perturb identity. This is
    the DEDUP_TOKEN analogue for the HTTP path — reproducibility of this
    hash is the whole guarantee."""
    rules_sorted = sorted(evidence_rules, key=lambda r: r.name)
    rules_joined = _HTTP_ID_RECORD_SEP.join(
        f"{r.name}{_HTTP_ID_GROUP_SEP}{r.kind}{_HTTP_ID_GROUP_SEP}{r.pattern}"
        for r in rules_sorted)
    payload = (endpoint_path_norm + _HTTP_ID_UNIT_SEP
               + method.upper() + _HTTP_ID_UNIT_SEP
               + str(int(status)) + _HTTP_ID_UNIT_SEP
               + rules_joined)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _match_rules(http: HttpEvidence, rules) -> tuple[list, list]:
    """Return (body_hits, side_channel_hits) as lists of rule names."""
    body = http.response_body or ""
    headers_joined = "\n".join(f"{n}: {v}" for n, v in http.response_headers)
    channels = dict(http.side_channel)
    body_hits: list[str] = []
    channel_hits: list[str] = []
    for r in rules:
        if r.kind == "response_body_regex":
            if re.search(r.pattern, body):
                body_hits.append(r.name)
        elif r.kind == "response_header_regex":
            if re.search(r.pattern, headers_joined):
                body_hits.append(r.name)
        elif r.kind == "side_channel_flag":
            if channels.get(r.name) == r.pattern:
                channel_hits.append(r.name)
        elif r.kind == "side_channel_regex":
            v = channels.get(r.name, "")
            if re.search(r.pattern, v):
                channel_hits.append(r.name)
        else:
            raise ValueError(f"unknown evidence rule kind: {r.kind!r}")
    return body_hits, channel_hits


def _http_reading(state: str, why: str, http: HttpEvidence,
                  pristine_http, body_hits, channel_hits,
                  observed_id: str = "") -> dict:
    """Assemble the HTTP reading dict — superset of the sanitizer shape."""
    return {
        "state": state,
        "why": why,
        "kind": "http",
        "http_status": http.status,
        "http_evidence_hits": tuple(body_hits),
        "side_channel_hits": tuple(channel_hits),
        "observed_http_id": observed_id,
        "pristine_http_id": (pristine_http.identity_hash
                             if pristine_http is not None else ""),
        "id_matches_pristine": bool(
            pristine_http is not None
            and observed_id
            and observed_id == pristine_http.identity_hash),
    }


def _classify_http(http, pristine_http, rules=None) -> dict:
    """Read one HTTP exchange into exactly one of the four states.

    Rules come from `pristine_http.evidence_rules` if present, otherwise
    from the `rules=` argument (needed for first reproduce, when pristine
    does not exist yet). At least one must be supplied — a classifier
    with no rules could never call red, which is the wrong-by-design
    failure mode this whole module exists to prevent (silent-green).
    """
    if not isinstance(http, HttpEvidence):
        raise TypeError(f"http must be HttpEvidence, got {type(http).__name__}")
    if pristine_http is not None and not isinstance(pristine_http, HttpPristine):
        raise TypeError(
            f"pristine_http must be HttpPristine or None, "
            f"got {type(pristine_http).__name__}")

    active_rules = (tuple(pristine_http.evidence_rules)
                    if pristine_http is not None
                    else tuple(rules or ()))
    if not active_rules:
        raise TypeError(
            "http classifier requires evidence rules — pass pristine_http= "
            "(uses pristine.evidence_rules) or rules= (for first reproduce). "
            "A classifier without rules can never call red, which is the "
            "silent-green failure mode this whole module exists to prevent.")

    # 1. Transport layer — no response ⇒ HARNESS_FAULT, always. Silence
    # is not proof of a fix. This branch matches the sanitizer path's
    # "no marker + non-zero exit = harness_fault" reasoning.
    if http.status == 0 or http.transport_error:
        te = http.transport_error or "no_response"
        if te in _HTTP_HARNESS_TRANSPORT_ERRORS or http.status == 0:
            why = (f"http transport failure ({te})"
                   + (f": {http.transport_detail}" if http.transport_detail
                      else "") + " — nothing was demonstrated about the "
                   f"vulnerability, so this is not evidence the bug is "
                   f"absent either")
            return _http_reading(HARNESS_FAULT, why, http, pristine_http,
                                 [], [])
    if http.status < 0 or http.response_body_bytes < 0:
        return _http_reading(
            HARNESS_FAULT,
            f"malformed http evidence: status={http.status} "
            f"body_bytes={http.response_body_bytes}",
            http, pristine_http, [], [])

    # 2. Evaluate rules against evidence — the ONE place a "red" reading
    # can originate. If we skip this branch and reach a green, the tests
    # in test_http_classifier.py will catch it.
    body_hits, channel_hits = _match_rules(http, active_rules)
    any_hit = bool(body_hits or channel_hits)

    # 3. Compute observed identity — same formula as pristine, using
    # THIS execution's endpoint/method/status against the active rule set.
    observed_id = identity_hash_for(http.endpoint_path, http.method,
                                    http.status, active_rules)

    # 4. Classify.
    if any_hit:
        # Rule matched. Red if identity matches (or no pristine yet);
        # different_bug if identity diverges.
        if pristine_http is None:
            why = (f"http rule(s) matched: body={body_hits} "
                   f"side_channel={channel_hits}; no pristine yet — this "
                   f"reading establishes it")
            return _http_reading(CONFIRMED_RED, why, http, None,
                                 body_hits, channel_hits, observed_id)
        if observed_id == pristine_http.identity_hash:
            why = (f"http rule(s) matched: body={body_hits} "
                   f"side_channel={channel_hits}, identity matches pristine")
            return _http_reading(CONFIRMED_RED, why, http, pristine_http,
                                 body_hits, channel_hits, observed_id)
        # identity mismatch — name what diverged
        diffs = []
        if http.endpoint_path != pristine_http.endpoint_path_norm:
            diffs.append(
                f"endpoint {http.endpoint_path!r} != pristine "
                f"{pristine_http.endpoint_path_norm!r}")
        if http.method.upper() != pristine_http.method.upper():
            diffs.append(
                f"method {http.method!r} != pristine {pristine_http.method!r}")
        if int(http.status) != int(pristine_http.status):
            diffs.append(
                f"status {http.status} != pristine {pristine_http.status}")
        # Rule-set differences are impossible here (we used pristine's rules
        # when pristine is present), so the divergence must be in one of the
        # three components above. If none listed, the hash function is
        # broken — flag loudly rather than silently swallow.
        why = (f"http rule(s) matched: body={body_hits} "
               f"side_channel={channel_hits}, but identity differs from "
               f"pristine: "
               f"{'; '.join(diffs) if diffs else '(unknown component)'}")
        return _http_reading(DIFFERENT_BUG, why, http, pristine_http,
                             body_hits, channel_hits, observed_id)

    # 5. No rule matched. HTTP-kind green requires AFFIRMATIVE evidence
    # that each declared rule was reached with a non-vulnerable reading —
    # not silent absence. Closes the D-shape bug where an exploit fires,
    # the reproducer emits a marker under the wrong name, side_channel
    # is empty, and the classifier falls through to green.
    channels = dict(http.side_channel)
    unreached_rules = []
    for r in active_rules:
        if r.kind == "side_channel_flag":
            if r.name not in channels:
                unreached_rules.append(f"{r.name}(side_channel_flag)")
        elif r.kind == "side_channel_regex":
            if not http.side_channel:
                unreached_rules.append(f"{r.name}(side_channel_regex)")
        elif r.kind == "response_body_regex":
            if http.response_body_bytes == 0:
                unreached_rules.append(f"{r.name}(response_body_regex)")
        elif r.kind == "response_header_regex":
            if not http.response_headers:
                unreached_rules.append(f"{r.name}(response_header_regex)")

    if unreached_rules:
        why = (f"http rule(s) declared but the reproducer produced no "
               f"reading against them: {unreached_rules}. This is silent "
               f"absence, not affirmative absence of the bug — the "
               f"reproducer's marker convention likely diverged from the "
               f"rule name(s). Refusing green; treating as harness_fault. "
               f"See spec.http.evidence_rules and PROVISION_SYSTEM "
               f"contract (#PW_SC name=value).")
        return _http_reading(HARNESS_FAULT, why, http, pristine_http,
                             [], [], observed_id)

    if pristine_http is None:
        why = ("no http rule matched but every declared rule had "
               "affirmative negative evidence; no pristine yet — this "
               "reading establishes 'affirmatively no red evidence'")
        return _http_reading(CONFIRMED_GREEN, why, http, None,
                             [], [], observed_id)

    # Pristine present. Check status against expected-green set.
    expected = pristine_http.expected_green_statuses
    if expected is None:
        # Default: any status that isn't the pristine's counts as green.
        # A response at the pristine status with no rules is inconclusive.
        status_ok = int(http.status) != int(pristine_http.status)
    else:
        status_ok = int(http.status) in expected

    # Negative body fingerprints — words in the response that mean the
    # bug is present even if the top-level regex was tightened by a
    # partial fix. Default: empty list.
    neg = pristine_http.body_fingerprint_negative_list or ()
    body_text = http.response_body or ""
    neg_hit = next((n for n in neg if n and n in body_text), None)

    if not status_ok:
        why = (f"no http rule matched, but response status {http.status} "
               f"matches pristine — cannot distinguish 'partially fixed' "
               f"from 'still vulnerable, rule too narrow'. Declare "
               f"expected_green_statuses on the pristine to disambiguate.")
        return _http_reading(HARNESS_FAULT, why, http, pristine_http,
                             [], [], observed_id)
    if neg_hit:
        why = (f"no http rule matched, but response body contains "
               f"pristine negative fingerprint {neg_hit!r} — "
               f"vulnerability signal present, patch is not complete")
        return _http_reading(HARNESS_FAULT, why, http, pristine_http,
                             [], [], observed_id)
    if http.total_s < 0.001:
        why = (f"no http rule matched, but total_s={http.total_s} is "
               f"suspiciously fast — refusing to call this green against "
               f"a possibly-mocked harness")
        return _http_reading(HARNESS_FAULT, why, http, pristine_http,
                             [], [], observed_id)

    why = (f"no http rule matched (status {http.status}, "
           f"ttfb {http.time_to_first_byte_s})")
    return _http_reading(CONFIRMED_GREEN, why, http, pristine_http,
                         [], [], observed_id)


def is_red(reading: dict) -> bool:
    """Strict. Only confirmed_red is red — never "not green"."""
    return reading.get("state") == CONFIRMED_RED


def is_green(reading: dict) -> bool:
    """Strict. Only confirmed_green is green — never "not red"."""
    return reading.get("state") == CONFIRMED_GREEN


def describe(reading: dict) -> str:
    return (f"{reading['state']} (exit {reading['returncode']}, marker "
            f"{'present' if reading['marker_present'] else 'ABSENT'}, token "
            f"{reading['dedup_token']}) — {reading['why']}")
