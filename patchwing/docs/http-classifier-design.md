# HTTP-shape classifier — design (pass 1 of the provision line)

**Status:** design only. Nothing implemented. Awaits sign-off before code.

**Scope:** replace the single-purpose `states.classify()` with a dispatched
router. Sanitizer path unchanged. New `http` path added as a real sibling.
This lets a future `provision` stage prove **CONFIRMED_RED** against an
HTTP-shape reproducer (curl → response) the same way the sanitizer path
proves it against an ASan/MSan trace. The `reproducer_lock` and every
downstream gate (patch/verify/package) work as-is — they read the lock's
pristine identity through the same key names, and the new HTTP fields sit
beside the existing ones, not in a parallel structure.

**Guardrail (repeated verbatim from Jay's brief):** the classifier's
`CONFIRMED_RED` must come from **evidence**, not from "curl didn't error."
No path in this design lets `provision` or any caller manufacture a red
without the classifier reading concrete evidence — a matched signature in
the response, or a named side-channel observation.

---

## 1. Dispatch

`states.classify()` becomes a router. **`kind` is a required positional
argument** — no default. Every existing call site must add `kind="sanitizer"`
before the router will accept the call. That protects against a caller
becoming HTTP by accident when a new parameter is added later.

### New signature

```python
def classify(
    kind: str,                        # "sanitizer" | "http"     REQUIRED
    *,
    # ---- sanitizer inputs (used only when kind == "sanitizer") ----
    returncode: int | None = None,
    output: str | None = None,
    pristine_token: str = "",
    timed_out: bool = False,
    # ---- http inputs (used only when kind == "http") ----
    http: HttpEvidence | None = None,
    pristine_http: HttpPristine | None = None,
) -> dict:
    """Route to the sanitizer or HTTP classifier. Kind is not inferred."""
```

Rules:

- `kind` is positional-only and required. `classify()` and
  `classify(returncode=0, output="")` both raise `TypeError`. Old-style
  positional calls (`classify(rc, out, tok, to)`) raise `TypeError` too —
  every existing call site is edited in the same pass.
- If `kind == "sanitizer"`: `returncode` and `output` are required (raise
  otherwise). `http` and `pristine_http` are ignored.
- If `kind == "http"`: `http` is required. `pristine_http` is optional
  (absent on the very first reproduce, exactly like `pristine_token` on
  the sanitizer path).
- Any other `kind` raises `ValueError` — no silent fall-through, no
  "well, try sanitizer."
- The router calls one of two internal implementations (`_classify_sanitizer`,
  `_classify_http`). Sanitizer body is the current `classify` renamed.
- **Return shape is a superset dict.** Every reading carries a `state`,
  `why`, `kind`, plus the fields relevant to its kind. Callers that only
  care about `state`/`is_red`/`is_green` (the vast majority) keep working
  without knowing which kind fired. Kind-specific fields let auditors
  reconstruct what was actually observed.

### Return shape (both kinds)

```
{
    "state":  "confirmed_red" | "confirmed_green" | "different_bug" | "harness_fault",
    "why":    str,           # human explanation
    "kind":   "sanitizer" | "http",
    # ---- sanitizer-only when kind == "sanitizer" ----
    "returncode": int,
    "timed_out":  bool,
    "marker":     str,       # "" if none, exact matched text otherwise
    "marker_present": bool,
    "dedup_token":     str,  # "" if none
    "pristine_token":  str,  # "" if none
    "token_matches_pristine": bool,
    # ---- http-only when kind == "http" ----
    "http_status":     int,   # 0 if no response was received
    "http_evidence_hits": [str, ...],  # names of matched signature rules
    "side_channel_hits": [str, ...],   # names of observed side-channel rules
    "pristine_http_id": str,  # sha256 hex, "" if no pristine
    "observed_http_id": str,  # sha256 hex — always computed if kind=http
    "id_matches_pristine": bool,
}
```

The `is_red()` / `is_green()` / `describe()` helpers stay strict and
kind-agnostic — they only read `state`.

---

## 2. HTTP-shape input struct

Two frozen dataclasses in `states.py`. Frozen because they represent an
observation; mutating them after classification would corrupt the audit
trail.

### `HttpEvidence` — what the reproducer captured

```python
@dataclass(frozen=True)
class HttpEvidence:
    # --- request the reproducer sent (recorded verbatim for audit) ---
    method: str                     # "GET" | "POST" | ...
    endpoint_path: str              # normalized, see below; "" if never sent
    request_headers: tuple[tuple[str, str], ...]  # ordered
    request_body_sha256: str        # hash only — never store attacker payload as bytes
    # --- response received (or absence-of) ---
    status: int                     # HTTP status; 0 iff no response bytes at all
    response_headers: tuple[tuple[str, str], ...]  # lowercased names
    response_body: str              # decoded text; truncated at 32KB with a marker
    response_body_bytes: int        # untruncated length, for audit
    # --- timing ---
    time_to_first_byte_s: float | None   # None iff no bytes received
    total_s: float
    # --- transport failure kinds, populated iff status == 0 ---
    transport_error: str            # "" if OK, else one of the recognised strings
                                    # (see HARNESS_FAULT list). Free-form detail
                                    # follows in transport_detail.
    transport_detail: str
    # --- side-channel observations recorded by the reproducer harness ---
    # e.g. {"pwn_file_created": True, "pwn_file_path": "/tmp/PW_PASS1_PWNED.17..."},
    # {"subprocess_spawned": True, "argv0": "id"}, etc.
    # Keys MUST match a rule name in the finding's signature spec (see below).
    side_channel: tuple[tuple[str, str], ...]  # ordered dict-of-strings
```

**Normalizations, done by the reproducer harness before building the struct:**

- `endpoint_path`: strip query string; lowercase scheme+host; keep path
  exactly. Never store query params — they carry the payload and would
  contaminate the pristine identity.
- `request_body_sha256`: computed BEFORE building the struct; the raw body
  is never carried in evidence. This is intentional: the payload is
  attacker-controlled, and storing it in the lock would create a payload
  cache in every evidence bundle.
- `response_headers`: header names lowercased; values verbatim; order
  preserved (some vulns rely on header order).
- `response_body`: only the first 32KB stored — truncation marker
  `"\n\n[patchwing: response body truncated at 32768 bytes]"` appended so
  it's obvious in the audit. Full byte count kept in `response_body_bytes`.

### `HttpPristine` — what the wall froze on unpatched code

```python
@dataclass(frozen=True)
class HttpPristine:
    endpoint_path_norm: str         # same normalization as HttpEvidence.endpoint_path
    method: str                     # "GET" | ...
    status: int                     # the status the pristine reproducer saw
    evidence_rules: tuple[EvidenceRule, ...]     # named regex/side-channel rules
    identity_hash: str              # sha256 hex — see §3
```

### `EvidenceRule` — one named signal

```python
@dataclass(frozen=True)
class EvidenceRule:
    name: str                       # stable name, appears in classifier output
                                    # e.g. "ognl_id_uid_reflection", "pwn_file_created"
    kind: str                       # "response_body_regex" | "response_header_regex"
                                    # | "side_channel_flag" | "side_channel_regex"
    pattern: str                    # regex source; verbatim string for flag rules
```

Rules are named so auditors read "matched rule `pwn_file_created`" instead
of a raw regex — same reason ASan's `SUMMARY:` lines are named markers,
not raw stack frames.

---

## 3. Pristine-identity hash for HTTP

The DEDUP_TOKEN analogue. `HttpPristine.identity_hash` is computed at wall-
freeze time by the reproduce stage, before any patch exists:

```
identity_hash = sha256(
    endpoint_path_norm + "\x1f" +
    method.upper() + "\x1f" +
    str(status) + "\x1f" +
    "\x1e".join(
        f"{r.name}\x1d{r.kind}\x1d{r.pattern}"
        for r in sorted(evidence_rules, key=lambda r: r.name)
    )
).hexdigest()
```

- ASCII unit separator (`\x1f`) between fields, record separator (`\x1e`)
  between rules, group separator (`\x1d`) within a rule. These bytes cannot
  appear in a normalized URL path or a rule name, so no ambiguous joins.
- Rules sorted by `name` so rule-order in the spec file does not perturb
  the hash. **Reproducibility of the hash is the whole guarantee.**
- Status IS in the hash — a vuln that returns 500 on the payload but 200
  on a benign request is a different fingerprint than one that returns
  200 on both. This mirrors sanitizer where the marker text (`ERROR: MSan`
  vs `SUMMARY: ASan`) is part of identity.
- Request headers, response headers, body content are NOT in the hash —
  those are per-execution evidence, not identity. Same principle as
  sanitizer: exit code varies run-to-run but is not identity.

The observed identity is computed at every subsequent execution with the
same formula, using the OBSERVED status, rules that matched, and normalized
endpoint. If `observed_http_id == pristine_http_id`, it's the same bug.
Mismatch → `DIFFERENT_BUG` (see §7).

---

## 4. CONFIRMED_RED conditions

An HTTP reading is `CONFIRMED_RED` iff **all of**:

1. `status != 0` — a response was received. (No response → HARNESS_FAULT.)
2. At least one of:
   - **≥1 evidence rule of kind `response_body_regex` or
     `response_header_regex` matched** — the pattern was found in the
     response.
   - **≥1 evidence rule of kind `side_channel_flag` or `side_channel_regex`
     matched** — the reproducer harness reported the named observation
     (e.g. `pwn_file_created: True` matched by rule
     `{name: "pwn_file_created", kind: "side_channel_flag", pattern: "True"}`).
3. If `pristine_http` is present: `observed_http_id == pristine_http_id`.
   (If pristine is absent — first reproduce — this condition is skipped,
   exactly analogous to sanitizer's `pristine_token=""` first-reproduce
   path. This first-reproduce reading is what ESTABLISHES the pristine.)

The `http_evidence_hits` and `side_channel_hits` fields on the return dict
list the rule names that matched — so the audit trail records not just
"red" but "red because rules `[a, b]` matched."

**Not RED, explicitly:**

- Status 200 with no rule matches → NOT red. `pristine_http` may pin a red
  at status 200, but only if a rule fires. A bare 200 means "the server
  responded," not "the exploit worked."
- Status 500 with no rule matches → NOT red. Servers 500 for many reasons.
  A 500 that reflects the OGNL payload in the error message is red, but
  the 500 itself is not.
- Rule matches but hash mismatch → NOT red (see §7).

---

## 5. CONFIRMED_GREEN conditions

An HTTP reading is `CONFIRMED_GREEN` iff **all of**:

1. `status != 0` — the container responded. Green requires a response;
   silence is not proof of a fix.
2. **Zero evidence rules matched** — no body regex, no header regex, no
   side-channel flag.
3. `status` is in the finding's `GreenSpec.expected_statuses` (a small
   allow-list on the finding spec — e.g. `[400, 403, 404, 422]` for a
   sanitized input rejection). The default if unspecified is
   `{s for s in range(200, 600) if s != pristine.status}` — i.e. "any
   status that isn't the red status." Explicit is strongly preferred.
4. If `pristine_http` is present, the response body does not contain any
   substring from `pristine.body_fingerprint_negative_list`. This list is
   OPTIONAL and lets an operator declare "these words in the response mean
   OGNL still evaluated, even if the top-level regex was tightened by a
   partial fix." Default empty list.
5. Response time was ≥ 0.001s (i.e. an actual response, not a synthetic
   zero-time reply — defensive against a mocked-out harness returning
   fake evidence).

**Not GREEN, explicitly:**

- Any rule match → NOT green, even if status is in the expected-green set.
- Timeout / transport error → HARNESS_FAULT, not green (silence ≠ fixed).
- Status 200 with no rule matches → green only if 200 is in the
  expected-green set. If the finding's spec doesn't declare it, default is
  "any status that isn't pristine's" — so a pristine-red-at-500 finding
  treats 200 as green by default. A pristine-red-at-200 finding must
  declare its expected-green statuses explicitly.

---

## 6. HARNESS_FAULT conditions

Any of:

- `status == 0` AND `transport_error` is one of:
  - `"connection_refused"` — container not listening
  - `"dns_failure"` — hostname didn't resolve
  - `"tls_error"` — TLS handshake failed (any cause)
  - `"connection_reset"` — server closed before any bytes
  - `"timeout_before_first_byte"` — TTFB exceeded; treat as no-signal
  - `"container_never_listened"` — reproducer harness detected no listener
- Timeout after some bytes received (`time_to_first_byte_s` is not None
  but `total_s >= timeout_limit`): still HARNESS_FAULT — a partial response
  is not evidence of anything.
- `HttpEvidence` malformed (e.g. status = negative, or body length claims
  more than 32KB but marker missing): `HARNESS_FAULT` with a clear `why`.

**Never GREEN on absence.** This is the same rule as sanitizer HARNESS_FAULT
— silence is not proof.

Downstream: the reproduce stage already handles HARNESS_FAULT with
`StageResult.fail` (`stages.py:1023-1030`), which retries with attempt
count. No change needed there.

---

## 7. DIFFERENT_BUG for HTTP

Reading is `DIFFERENT_BUG` iff:

- At least one evidence rule matched (i.e. it would be RED under §4
  without the identity check), AND
- `pristine_http` is present, AND
- `observed_http_id != pristine_http_id`.

Concrete example: pristine is CVE-2017-5638 with
`endpoint_path_norm="/showcase/index.action"`, `status=200`, and rule
`ognl_id_uid_reflection`. A later reproduce hits
`/showcase/showcase.action` (typo? changed spec?), gets 200, matches
`ognl_id_uid_reflection`. Same rule, same status — but the normalized
endpoint changed, so `identity_hash` differs. `DIFFERENT_BUG`, with `why`
naming which component of identity diverged:

```
"http rule(s) matched but the pristine identity does not: "
"observed_endpoint_path=/showcase/showcase.action but pristine was "
"/showcase/index.action (same rule ognl_id_uid_reflection)"
```

This mirrors the sanitizer `DIFFERENT_BUG` reasoning: "a sanitizer fired
but the crash identity differs from the pristine reproducer." A rule that
fires on the wrong endpoint is a rule that reveals a different vulnerability
— honest to say so, corrupting to fold into red.

The classifier's `why` explicitly names WHICH component of the identity
diverged (endpoint vs status vs rule-set) so the audit reader can tell at
a glance whether the finding drifted, the target changed, or an operator
misconfigured a rule.

---

## 8. Reproducer lock — extensions

**Same lock artifact. Same table. No parallel format.** The kind is a
field on the manifest, not a new artifact kind. Every downstream reader
(patch @ `stages.py:2151`, verify @ `stages.py:2765`, package @
`stages.py:3468`) already loads via `s.latest_artifact(f.id,
"reproducer_lock")` and JSON-parses; they will simply see new keys.

### Fields added to `manifest` (the JSON content of `reproducer_lock`)

Alongside the existing keys (`files`, `n_files`, `n_reproducer`,
`algorithm`, `pristine_dedup_token`, `pristine_marker`,
`pristine_returncode`):

```json
{
  "pristine_kind": "http",             // "sanitizer" | "http"; default "sanitizer"
                                       // for backward compat with existing locks
  "pristine_http": {                   // present iff pristine_kind == "http"
    "endpoint_path_norm": "...",
    "method": "GET",
    "status": 200,
    "evidence_rules": [
      {"name": "ognl_id_uid_reflection",
       "kind": "response_body_regex",
       "pattern": "uid=\\d+\\(.+?\\)"},
      {"name": "pwn_file_created",
       "kind": "side_channel_flag",
       "pattern": "True"}
    ],
    "identity_hash": "sha256hex..."   // matches HttpPristine.identity_hash
  }
}
```

### Fields added to the artifact `meta` dict (used by fast readers that don't parse content)

Alongside the existing keys (`n_files`, `n_reproducer`, `algorithm`,
`pristine_dedup_token`):

```
"pristine_kind": "http",             // MUST be set on every new lock
"pristine_http_id": "sha256hex..."   // present iff kind == "http"
```

### Backward compatibility

- **Old sanitizer locks** have no `pristine_kind` key. Every reader that
  needs the kind treats `absent` as `"sanitizer"`. Nothing in the corpus
  breaks.
- The existing `pristine_dedup_token` field is present-and-non-empty on
  sanitizer locks, absent (or empty string) on HTTP locks. Callers should
  branch on `pristine_kind`, not on presence of `pristine_dedup_token`
  (defensive — some future kind might reuse the token field).
- The `algorithm` field stays `"sha256"` for both kinds — same hash
  function is used for file contents in the wall AND for the HTTP
  identity hash.

### Which stages need to be kind-aware after Pass 1

Only three, and only for the classifier dispatch:

1. Reproduce (`stages.py:988`, `stages.py:1077-1093`) — read the finding
   spec to know what kind to build evidence for; freeze the lock with the
   right `pristine_kind`.
2. Investigation loop inside patch (`stages.py:1514-1544`) — read the
   lock's `pristine_kind`; if `"http"`, build `HttpEvidence` from the
   post-patch reproducer run and call `classify(kind="http", http=...,
   pristine_http=<from lock>)`.
3. Verify (`stages.py:3011`) — same pattern as investigation loop.

**Pass 1 does NOT touch stages 1-3.** Pass 1 only ships:

- The dispatched `classify()`.
- The `HttpEvidence` / `HttpPristine` / `EvidenceRule` dataclasses in
  `states.py`.
- Unit tests exercising every HTTP path.
- The Pass-1 end-to-end proof against a hand-crafted local Flask target,
  driven by a standalone script (not a stage) that calls `classify()`
  directly and writes a lock artifact to a scratch store. The point of
  Pass 1 is to prove the classifier and the lock format work; wiring them
  into `stages.py` is Pass 2's job.

---

## Rejected alternatives (recorded to prevent re-litigation)

- **`kind` auto-detected from input shape** — rejected. A caller that
  forgets to pass one field could silently switch classifier. Explicit
  opt-in is safer.
- **Two `classify()` functions with different names** — rejected. Would
  need a second dispatch layer at every call site; kind arg centralizes
  it in one router.
- **Parallel `reproducer_lock_http` artifact kind** — rejected explicitly
  in the brief. Downstream readers would have to know both names; a bug
  writer that forgot to check the second name would silently accept any
  patch on an HTTP-kind finding. One lock table, one reader.
- **Store the raw HTTP payload in evidence** — rejected. Attacker-
  controlled bytes should not live in an artifact bundle. Hash of the
  request body is enough for audit.
- **Fold status into the pristine token string** — rejected. String
  concatenation makes the identity opaque; explicit sha256 with named
  separators is what the sanitizer-side reasoning called for and the
  HTTP-side should mirror.

---

## Resolved (Jay, 2026-08-05)

1. **First-reproduce ergonomics — caller reconstructs.** Symmetric with
   the sanitizer path (`stages.py:1077-1084`, where the caller reads
   `reading["dedup_token"]`, `reading["marker"]`, and `res.returncode`
   and folds them into the lock manifest itself). The HTTP classifier
   returns the reading dict only — no richer `HttpPristine` return
   object. The caller already holds:
   - The `evidence_rules` (loaded from the finding's spec — see item 2).
   - The `HttpEvidence` it just passed in (endpoint, method, status).
   - The `observed_http_id` string on the returned reading dict.
   That is exactly enough to construct `HttpPristine(...)` inline and
   hand it to the lock writer, the same shape the sanitizer path uses.

## Out of scope for Pass 1 (recorded so we don't re-litigate)

- **Where `EvidenceRule` entries come from.** Pass 1 rules are HAND-
  AUTHORED and stored in the finding's **spec artifact** as a single
  source of truth. No operator UI, no fix-commit derivation, no
  auto-generation. The Pass 1 end-to-end proof authors its rules
  directly in the driver script. Sourcing (operator UI vs derivation
  from fix commit vs manual TOML block in the spec) is Pass 2's problem
  — the classifier itself is neutral to where its rules were sourced.

- **Multi-step / multi-request reproducers.** Pass 1 is single-request
  only (one `HttpEvidence` → one classification). Struts CVE-2017-5638
  is a single POST with a crafted `Content-Type` header, so Pass 1's
  future consumer works. Multi-step exploits (login → CSRF → upload →
  trigger) are DEFERRED — they are NOT folded into the classifier's
  input shape now. When we get there, `HttpEvidence` becomes a tuple of
  request/response pairs and `HttpPristine.identity_hash` incorporates
  the ordered endpoint sequence, but that is a later pass and does not
  block Pass 1.
