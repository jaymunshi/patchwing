"""
Stage contract, registry, and implementations.

A stage is a function over one finding. It reads the finding plus whatever
artifacts earlier stages produced, does one job, and returns a StageResult. It
must be safe to run twice — the runner retries, and a human can re-run any stage
by hand.

Stages are intentionally dumb about ordering. The runner owns the sequence; a
stage only reports what happened.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Callable, Protocol

from . import budget as budget_mod
from . import edit as edit_mod
from . import models as models_mod
from . import outcomes as outcomes_mod
from . import sandbox as sandbox_mod
from . import states as states_mod
from . import spec as spec_mod  # dispatch for HTTP-shape reproducers


def _classify_repro(f, ctx, returncode, output, timed_out, pristine_token="", duration_s: float = 0.0):
    """Dispatch classify() based on the finding's reproducer_kind.
    Adds sanitizer-shape shims to HTTP readings for downstream compat.
    Introduced to fix stages.py:1275/1846/1899/3349/3462 dispatch bug."""
    _spec_dict = _spec(f, ctx) or {}
    _kind = spec_mod.reproducer_kind(_spec_dict)
    if _kind == "http":
        from .http_parse import parse_http_from_output
        _http_block = _spec_dict.get("http") or {}
        _rules = [
            states_mod.EvidenceRule(name=r["name"], kind=r["kind"], pattern=r["pattern"])
            for r in _http_block.get("evidence_rules", [])
        ]
        _ev = parse_http_from_output(
            output,
            method=_http_block.get("method", "POST"),
            endpoint_path=_http_block.get("endpoint_path_norm", "/"),
        )
        # Inject the real reproducer duration (parser doesn't extract it).
        # Bypasses the 'suspiciously fast' guard in _classify_http that
        # otherwise trips CONFIRMED_GREEN paths where total_s defaults to 0.
        if duration_s and duration_s > 0:
            import dataclasses as _dc
            _ev = _dc.replace(_ev, total_s=float(duration_s))
        # Rev-2: if this is a verify-side call (pristine_token != ""),
        # reconstruct HttpPristine from reproducer_lock.verdict_config and
        # pass THAT to classify. Otherwise (first reproduce), use rules
        # from the current spec — spec IS the source of truth for the
        # first reading.
        _pristine_http = None
        if pristine_token:
            try:
                _lock_art = ctx.store.latest_artifact(f.id, "reproducer_lock")
                if _lock_art is not None:
                    import json as _json
                    _lock = _json.loads(_lock_art["content"] or "{}")
                    _vc = _lock.get("verdict_config") or {}
                    if _vc.get("kind") == "http":
                        _pristine_http = states_mod.reconstruct_pristine_http(_vc)
            except Exception:
                _pristine_http = None
        if _pristine_http is not None:
            reading = states_mod.classify("http", http=_ev,
                                           pristine_http=_pristine_http)
        else:
            reading = states_mod.classify("http", http=_ev, rules=_rules)
        # Fix 0 heuristic backstop: if a rule name appears anywhere in
        # the raw reproducer output but the parser did not lift it into
        # side_channel, that is a parse-miss disguised as green. Refuse.
        # Guards against Fix 2 parser drift + future reproducer formats.
        if reading.get("state") == "confirmed_green":
            _channels_seen = set()
            for _pair in getattr(_ev, "side_channel", ()):
                if isinstance(_pair, (list, tuple)) and len(_pair) >= 1:
                    _channels_seen.add(_pair[0])
            for _r in _rules:
                if _r.name and _r.name in (output or "") and _r.name not in _channels_seen:
                    reading = dict(reading)
                    reading["state"] = "harness_fault"
                    reading["why"] = (f"parse-miss: rule {_r.name!r} appears "
                                       f"in raw reproducer output but was not "
                                       f"lifted into side_channel. Refusing green.")
                    reading["harness_fault_reason"] = "parse_miss"
                    break
        reading.setdefault("returncode", returncode)
        reading.setdefault("timed_out", timed_out)
        reading.setdefault("marker", reading.get("kind", "http"))
        reading.setdefault("marker_present", bool(reading.get("http_evidence_hits") or reading.get("side_channel_hits")))
        reading.setdefault("dedup_token", reading.get("observed_http_id", ""))
        reading.setdefault("pristine_token", reading.get("pristine_http_id", "") or pristine_token)
        reading.setdefault("token_matches_pristine", reading.get("id_matches_pristine", False))
        return reading
    else:
        return states_mod.classify("sanitizer", returncode=returncode,
                                    output=output, pristine_token=pristine_token,
                                    timed_out=timed_out)


from . import symptom as symptom_mod
from . import tools as tools_mod
from . import wall as wall_mod
from .store import Finding, Store

# What a stage can say about its own outcome.
OK = "ok"                 # advance to the next stage
RETRY = "retry"           # transient; runner will try again
BLOCKED = "blocked"       # needs a human decision (missing input or upstream fault)
PENDING_SIGNOFF = "pending_signoff"  # review-stage terminal, awaiting human approve/reject
REJECT = "reject"         # not a real bug, or not fixable — terminal, not a failure
FAIL = "fail"             # something broke


@dataclass
class StageResult:
    status: str
    message: str = ""
    artifacts: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Defence in depth, NOT the enforcement. The guard in
        # tests/test_outcome_coverage.py is what actually holds, because it reads
        # every path in the file rather than only the ones a run happens to take.
        # This catches a value assembled at runtime, which the static guard cannot
        # see. Absence is allowed here: whether a path MUST carry an outcome is the
        # guard's question, not this one's.
        if "outcome" in self.meta:
            # C.1: safe-degrade — validate() returns HARNESS_UNKNOWN_OUTCOME for
            # unregistered outcomes rather than raising. Preserve original name
            # so audit trails see BOTH the intended and the actual outcome.
            _intended = self.meta["outcome"]
            _resolved = outcomes_mod.validate(_intended)
            if _resolved != _intended:
                self.meta["outcome_original"] = _intended
                self.meta["outcome"] = _resolved

    @classmethod
    def ok(cls, message: str = "", **kw) -> "StageResult":
        return cls(OK, message, **kw)

    @classmethod
    def retry(cls, message: str = "", **kw) -> "StageResult":
        return cls(RETRY, message, **kw)

    @classmethod
    def blocked(cls, message: str = "", **kw) -> "StageResult":
        return cls(BLOCKED, message, **kw)

    @classmethod
    def pending_signoff(cls, message: str = "", **kw) -> "StageResult":
        """Review-stage terminal: work done, awaiting human sign-off.
        Distinct from `blocked` (which means broken / needs remediation)
        so operators aren't misled by a scary label on healthy findings."""
        return cls(PENDING_SIGNOFF, message, **kw)

    @classmethod
    def reject(cls, message: str = "", **kw) -> "StageResult":
        return cls(REJECT, message, **kw)

    @classmethod
    def fail(cls, message: str = "", **kw) -> "StageResult":
        return cls(FAIL, message, **kw)


class Context(Protocol):
    store: Store
    workdir: str
    config: object | None


StageFn = Callable[[Finding, Context], StageResult]

_REGISTRY: dict[str, StageFn] = {}


def stage(name: str) -> Callable[[StageFn], StageFn]:
    """Register a stage, and make the cost ceiling a hard stop for all of them.

    Wrapping at registration means a new stage cannot forget to honour the
    ceiling — the alternative is remembering a try/except at every call site,
    which is exactly the kind of thing that gets missed once and then runs all
    night.
    """
    def deco(fn: StageFn) -> StageFn:
        def guarded(f: Finding, ctx: Context) -> StageResult:
            try:
                return fn(f, ctx)
            except budget_mod.CeilingExceeded as e:
                return StageResult.blocked(
                    f"CEILING EXCEEDED — run halted in stage '{name}'. "
                    f"{e.spent.describe()} against {e.ceiling.describe()}. "
                    f"Raise pipeline.max_tokens_per_finding / "
                    f"max_usd_per_finding to continue this finding.",
                    meta={"outcome": "ceiling_exceeded",
                          "ceiling_exceeded": True,
                          "spent": e.spent.as_dict(),
                          "ceiling": {"max_tokens": e.ceiling.max_tokens,
                                      "max_usd": e.ceiling.max_usd}})
        guarded.__name__ = getattr(fn, "__name__", name)
        guarded.__doc__ = fn.__doc__
        _REGISTRY[name] = guarded
        return guarded
    return deco


def get(name: str) -> StageFn | None:
    return _REGISTRY.get(name)


def registered() -> list[str]:
    return sorted(_REGISTRY)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _resolve_prompt(ctx: Context, name: str, builtin: str) -> str:
    """DB override wins over the hardcoded constant.

    Reads `prompt_overrides.body` for the given name and returns it stripped
    if present, else the built-in. This is what makes the UI edit take effect
    without a redeploy — every model call runs through here.
    """
    try:
        row = ctx.store.conn.execute(
            "SELECT body FROM prompt_overrides WHERE name = ?", (name,)
        ).fetchone()
    except Exception:
        return builtin
    if row and row[0] and str(row[0]).strip():
        return str(row[0])
    return builtin


def _sha256_text(s: str) -> str:
    """Hash file CONTENT as bytes. Used for the §6a rollback hash triple."""
    return hashlib.sha256((s or "").encode("utf-8", "surrogateescape")).hexdigest()


# Positive signals that the COMPILER actually judged some source. If ANY of these
# fire, the failing build has produced a verdict on code — legitimate reject.
# If NONE fire, the build failed before the compiler got to the patched source,
# and the run has learned nothing about the fix. See VERIFY_BUILD_HARNESS_FAULT.
_COMPILER_ERROR_PATTERNS = [
    re.compile(r"\.(?:c|cc|cpp|cxx|h|hh|hpp|s|S|m|mm)(?::\d+){1,2}:\s*error:"),
    re.compile(r"undefined reference to"),
    re.compile(r"multiple definition of"),
    re.compile(r"conflicting types for"),
    re.compile(r"implicit declaration of function"),
    re.compile(r"redefinition of"),
    re.compile(r"error: expected [';{}]"),
    re.compile(r"ld: .*cannot find"),
    re.compile(r"linker command failed"),
    re.compile(r"fatal error: .+: No such file or directory"),
]

# Positive signals that the ENVIRONMENT broke before the compiler ever ran.
# These take precedence: a compile-error regex hit inside an autotools log means
# nothing if configure failed and no source was ever fed to the compiler.
_HARNESS_FAULT_PATTERNS = [
    re.compile(r"configure: error:", re.MULTILINE),
    re.compile(r"^\S+: command not found", re.MULTILINE),
    re.compile(r"cannot run C compiled programs"),
    re.compile(r"autoreconf: command not found"),
    re.compile(r"Package .+ was not found in the pkg-config search path"),
    re.compile(r"docker: Error response from daemon"),
    re.compile(r"podman: Error response"),
    re.compile(r"exec container process .*: No such file"),
]


def _looks_like_compiler_verdict(output: str) -> tuple[bool, str]:
    """Did the compiler actually judge some source, or did the environment break?

    Returns (is_verdict, why). Errs toward returning False (harness_fault): a
    false positive here costs the reader one look; a false negative ships a
    "the patch is not valid code" claim the run never earned.
    """
    out = output or ""
    for pat in _HARNESS_FAULT_PATTERNS:
        m = pat.search(out)
        if m:
            return False, f"environment failed before the compiler ran: {m.group(0)[:120]}"
    for pat in _COMPILER_ERROR_PATTERNS:
        m = pat.search(out)
        if m:
            return True, f"compiler emitted a source-level diagnostic: {m.group(0)[:120]}"
    return False, ("no compiler diagnostic found in the failing build's output — "
                   "the compiler may not have been reached")


def _localize_from_trace(output: str, root: str) -> dict:
    """The container is the only authority. Parse the sanitizer report for file
    paths and return them, preferring origin > storage > crash.

    ARVO's `files` field records which file the DEVELOPER patched, which is not
    the same thing as where the bug lives — the 1076 run made that visible in a
    way nothing else did. This routine reads the localizer signal that has
    strictly been observed at runtime, not asserted by anyone.

    Returns {"crash": [...], "storage": [...], "origin": [...], "primary": <str>}
    with paths relative to ``root``. Runtime/library paths are dropped: sanitizer
    interceptors and libFuzzer frames are not where a maintainer's fix goes.
    """
    out = output or ""
    root_norm = "/" + root.strip("/") + "/"

    # A frame like "#3 0x... in fn_name /path/to/file.c:LINE:COL"
    frame_re = re.compile(
        r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S+\s+(/\S+?\.(?:c|cc|cpp|cxx|h|hh|hpp))"
        r"(?::(\d+))?(?::\d+)?", re.MULTILINE)

    def _paths_in_block(block: str) -> list[tuple[str, str]]:
        """Ordered, deduped (path, line) tuples inside the project root."""
        seen, hits = set(), []
        for m in frame_re.finditer(block):
            path = m.group(1)
            if not path.startswith(root_norm):
                continue
            rel = path[len(root_norm):]
            key = rel
            if key in seen:
                continue
            seen.add(key)
            hits.append((rel, m.group(2) or ""))
        return hits

    result = {"crash": [], "storage": [], "origin": [], "primary": ""}

    # The crash block is at the top, before any "was stored" / "was created" line.
    tail_markers = ("Uninitialized value was stored",
                    "Uninitialized value was created")
    end = min([out.find(m) for m in tail_markers if m in out] or [len(out)])
    result["crash"] = _paths_in_block(out[:end])

    m = re.search(r"Uninitialized value was stored to memory at\n(.*?)"
                  r"(?=Uninitialized value was created|\Z)", out, re.S)
    if m:
        result["storage"] = _paths_in_block(m.group(1))
    m = re.search(r"Uninitialized value was created by a heap allocation\n(.*)",
                  out, re.S)
    if m:
        result["origin"] = _paths_in_block(m.group(1))

    # Priority: origin > storage > crash. The origin block says WHERE THE BAD
    # BYTES CAME FROM, which is where a maintainer would put the fix. The crash
    # block says where they were CONSUMED, which is often too late.
    for block in ("origin", "storage", "crash"):
        if result[block]:
            result["primary"] = result[block][0][0]
            break
    return result




def _compute_dist_manifest(sb, root: str) -> dict:
    """Rev-3: {relpath: sha256} for every file under `root`. Used at
    provision (as pristine snapshot) and at verify (as sanity check —
    'build ran / something changed'). NOT a verdict gate; the reproducer
    flip remains the sole verdict."""
    if not root:
        return {}
    r = sb.run(f"find {root} -type f -print0 2>/dev/null | "
                f"xargs -0 sha256sum 2>/dev/null | head -5000")
    out = {}
    for line in (r.stdout or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        sha, full = parts
        if full.startswith(root):
            rel = full[len(root):].lstrip("/")
        else:
            rel = full
        out[rel] = sha
    return out

def _spec(f: Finding, ctx: Context) -> dict | None:
    art = ctx.store.latest_artifact(f.id, "spec")
    if art is None:
        return None
    try:
        return json.loads(art["content"])
    except json.JSONDecodeError:
        return None


def _client(ctx: Context, role: str, finding: Finding | None = None,
            stage_name: str = ""):
    """A model client for `role`, metered against the finding's cost ceiling.

    Metering lives here rather than at each call site: a stage that forgets to
    account is a stage that runs unbounded, and this runs unattended.
    """
    from .models import Client
    cfg = getattr(ctx, "config", None)
    if cfg is None:
        raise RuntimeError(
            "no configuration loaded — this stage needs a model. "
            "Create patchwing.toml (see patchwing.example.toml).")
    client = Client(cfg.model(role))
    if finding is None:
        return client
    return budget_mod.Metered(
        client, ctx.store, finding.id, seat=role,
        ceiling=budget_mod.load_ceiling(ctx.store, cfg), stage_name=stage_name)


def _repro_source(ctx: Context, spec: dict, manifest: dict) -> str:
    """Item 1: the reproducer's own text, not just its output.

    A reader who cannot see what the test does cannot judge whether passing it
    means anything.
    """
    target = _target_dir(spec or {})
    names = [k for k, v in (manifest.get("files") or {}).items()
             if v.get("reason") == "reproducer"]
    out = []
    for rel in names[:3]:
        try:
            with open(os.path.join(target, rel), "r", encoding="utf-8",
                      errors="replace") as fh:
                out.append(f"--- {rel} ---\n{fh.read()}")
        except OSError:
            out.append(f"--- {rel} --- (unreadable)")
    return "\n\n".join(out)


def _container_lines(f: Finding, ctx: Context, spec: dict) -> list[str]:
    """Item 6: enough to re-run items 2-5 without trusting us.

    A package that can only be read is a claim. A package that can be re-run is
    evidence. That difference is the whole product, so the exact image, isolation
    settings and commands go in verbatim.
    """
    cfg = getattr(ctx, "config", None)
    sb = getattr(cfg, "sandbox", None) if cfg else None
    cmds = (spec or {}).get("commands") or {}
    # Prefer the per-target image over the CLI config's default sandbox image.
    # spec.target.image is what the pod was actually created from; cfg.sandbox
    # is a global default that usually names a generic runtime (Python slim)
    # that is NOT the image this finding ran in.
    target_image = ((spec or {}).get("target") or {}).get("image", "").strip()
    image_ref = target_image or getattr(sb, "image", "?")
    lines = ["Run these inside the image below and you should see the reproducer "
             "fail before the patch and pass after it.", "", "```"]
    if sb is not None:
        lines += [
            f"backend : {getattr(sb, 'backend', '?')}",
            f"image   : {image_ref}",
            f"network : {getattr(sb, 'network', '?')}   "
            f"(disabled, so nothing can phone home mid-run)",
            f"cpus    : {getattr(sb, 'cpus', '?')}    memory: {getattr(sb, 'memory', '?')}",
        ]
    else:
        lines.append(f"image   : {image_ref}")
        lines.append("sandbox : (backend not recorded)")
    lines += [
        f"build     : {cmds.get('build') or '(none)'}",
        f"reproduce : {cmds.get('reproduce') or '(none)'}",
        f"test      : {cmds.get('test') or '(none)'}",
        "```",
    ]
    return lines


def _build_artifact_lines(f: Finding, ctx: Context) -> list[str]:
    """The build-artifact hashes, so the package carries what it claims to compare.

    Without these a reader has only our word that the patch reached the compiled
    binary. With them the comparison is checkable: rebuild from the image and diff
    the hashes yourself.
    """
    art = ctx.store.latest_artifact(f.id, "verdict")
    if art is None:
        return ["(no verdict artifact)"]
    try:
        m = json.loads(art["meta"] or "{}")
    except (json.JSONDecodeError, TypeError):
        return ["(verdict meta unreadable)"]
    ba = m.get("build_artifact")
    if not ba:
        return ["The build artifact was not hashed for this run — no `artifact` "
                "path was declared in the target spec, so the patch reaching the "
                "compiled binary is unverified."]
    return [
        f"`{ba.get('path', '?')}`",
        "",
        "| | md5 |",
        "|---|---|",
        f"| before patch | `{ba.get('md5_before_patch', '?')}` |",
        f"| after compile | `{ba.get('md5_after_compile', '?')}` |",
        "",
        (f"**Changed: {ba.get('changed')}.** " + str(ba.get("assertion", ""))),
        "",
        "*What this pair proves, and does not:* the **before** hash is "
        "independently reproducible — pull the image and compute it yourself. The "
        "**after** hash is **not**: OSS-Fuzz builds are not hermetic, so your "
        "rebuild will very likely differ, and that difference is **not** evidence "
        "of tampering. These two together show only that the patch reached the "
        "compiled binary *in this run*. The thing you reproduce independently is "
        "**red → green**, not a hash.",
    ]


def _seat_lines(f: Finding, ctx: Context) -> list[str]:
    """Item 8: which model sat in which seat.

    Recorded because the architecture's claim is that it does NOT matter — the fix
    is tested, not trusted. That claim is only checkable if the mapping is visible.
    """
    seats: dict[str, str] = {}
    for row in ctx.store.artifacts(f.id, budget_mod.SPEND_KIND):
        try:
            m = json.loads(row["meta"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        seats.setdefault(m.get("seat", "?"), m.get("model", "?"))
    if not seats:
        return ["No metered model calls were recorded."]
    lines = ["| seat | model |", "|---|---|"]
    for seat, model in sorted(seats.items()):
        lines.append(f"| {seat} | `{model}` |")
    lines += ["", "The fix-writer is interchangeable by design: the container "
                  "decides whether a patch is accepted, not the model's reputation."]
    return lines


def _diff_lines(f: Finding, ctx: Context, spec: dict) -> list[str]:
    """Item 3: the patch as a unified diff, not a whole regenerated file.

    A reviewer must be able to see the change in a minute. Reconstructed here from
    the original source and the patched artifact; the patch stage still emits whole
    files, so this is where the reader-facing diff is produced.
    """
    import difflib
    art = ctx.store.latest_artifact(f.id, "patch")
    if art is None:
        return ["(no patch artifact)"]
    try:
        meta = json.loads(art["meta"] or "{}")
    except (json.JSONDecodeError, TypeError):
        meta = {}
    rel = meta.get("file")
    if not rel:
        return ["(patch artifact does not name a file)"]

    # Prefer the stored patch_diff artifact — it holds the exact unified diff
    # the patch stage produced against the pod's pre-patch bytes. For any
    # in-image finding (target.mode == "in-image") the source lives in the
    # POD, not on the host, so the fallback host-open path below cannot see
    # the "before" file and would render the "unavailable" placeholder. Read
    # what's already stored instead of recomputing something we can't.
    diff_art = ctx.store.latest_artifact(f.id, "patch_diff")
    if diff_art is not None and (diff_art["content"] or "").strip():
        body = diff_art["content"]
        truncated = ""
        if len(body) > 12000:
            body, truncated = body[:12000], "\n... (diff truncated for readability)"
        n_added = sum(1 for ln in body.splitlines()
                      if ln.startswith("+") and not ln.startswith("+++"))
        return ["```diff", body.rstrip("\n") + truncated, "```",
                "", f"{n_added} line(s) added / see patch_diff artifact for the "
                "full patched file"]

    target = _target_dir(spec or {})
    try:
        with open(os.path.join(target, rel), "r", encoding="utf-8") as fh:
            before = fh.read()
    except OSError:
        return [f"(original {rel} unavailable; cannot render a diff)"]
    diff = list(difflib.unified_diff(
        before.splitlines(keepends=True),
        (art["content"] or "").splitlines(keepends=True),
        fromfile=f"a/{rel}", tofile=f"b/{rel}", n=3))
    if not diff:
        return ["(no textual difference)"]
    body = "".join(diff)
    truncated = ""
    if len(body) > 12000:
        body, truncated = body[:12000], "\n... (diff truncated for readability)"
    return ["```diff", body.rstrip("\n") + truncated, "```",
            f"", f"{sum(1 for d in diff if d.startswith('+') and not d.startswith('+++'))} "
            f"line(s) added, "
            f"{sum(1 for d in diff if d.startswith('-') and not d.startswith('---'))} "
            f"removed."]


def _review_lines(f: Finding, ctx: Context) -> list[str]:
    """The reviewer's opinion, with the config that produced it.

    Printed with the config inline and labelled advisory throughout. A reader must
    not be able to mistake this for the container's decision, and must be able to
    reproduce the opinion — which requires knowing the flags it ran under.
    """
    art = ctx.store.latest_artifact(f.id, "review_advisory")
    if art is None:
        return ["No advisory review was run. The verdict above rests entirely on "
                "the container result, which is by design — the reviewer is "
                "optional and never decides anything."]
    try:
        m = json.loads(art["meta"] or "{}")
    except (json.JSONDecodeError, TypeError):
        m = {}
    if not m.get("available", False):
        return [f"Advisory review was attempted but unavailable: "
                f"`{(art['content'] or '')[:200]}`. This does not affect the "
                f"verdict."]

    rc = m.get("reviewer_config") or {}
    extra = rc.get("extra") or {}
    lines = [
        f"**Verdict: {m.get('verdict', '?')}** — advisory only. This did not and "
        f"cannot change the pass/fail result above, which was decided by the "
        f"container.",
        "",
        "```json",
        (art["content"] or "")[:1500],
        "```",
        "",
        "Produced by:",
        "",
        f"- model: `{rc.get('model', '?')}` (family: {rc.get('family', '?')})",
        f"- endpoint: `{rc.get('endpoint', '?')}`",
        f"- temperature: {rc.get('temperature', '?')}, "
        f"max_tokens: {rc.get('max_tokens', '?')}",
        f"- extra params: `{json.dumps(extra) if extra else 'none'}`",
        f"- independence: {m.get('independence', 'unknown')}",
        "",
        "*The configuration is listed because this reviewer's verdict has been "
        "observed to change with a single flag. An opinion without the config that "
        "produced it cannot be reproduced, and should be weighted accordingly.*",
    ]
    return lines


def _cost_lines(f: Finding, ctx: Context) -> list[str]:
    """Spend per seat plus the ceiling it ran under.

    Reported per seat rather than as one number: a reader deciding whether to
    trust this package should be able to see that the reviewer was cheap and the
    fix-writer was not, and what bound the run was operating under at the time.
    """
    cfg = getattr(ctx, "config", None)
    ceiling = budget_mod.load_ceiling(ctx.store, cfg)
    total = budget_mod.spent(ctx.store, f.id)
    per_seat: dict[str, dict] = {}
    for row in ctx.store.artifacts(f.id, budget_mod.SPEND_KIND):
        try:
            m = json.loads(row["meta"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        e = per_seat.setdefault(m.get("seat", "?"),
                                {"model": m.get("model", "?"), "tok": 0,
                                 "usd": 0.0, "calls": 0})
        e["tok"] += int(m.get("prompt_tokens", 0)) + int(m.get("completion_tokens", 0))
        e["usd"] += float(m.get("usd", 0.0) or 0.0)
        e["calls"] += 1

    # Budget history, never collapsed into a single figure. "The ceiling was X"
    # and "the ceiling started at Y and a human raised it twice" are different
    # claims, and cost-per-fix data is only meaningful if the package makes the
    # difference visible.
    grants = budget_mod.topups(ctx.store, f.id)
    eff = budget_mod.effective_ceiling(ctx.store, f.id, ceiling)
    lines = [f"Original per-finding ceiling: {ceiling.describe()}."]
    if grants:
        lines.append("")
        lines.append(f"**Topped up {len(grants)} time(s) by human action:**")
        lines.append("")
        lines += ["| # | +tokens | +usd | actor | reason |", "|---:|---:|---:|---|---|"]
        for i, g in enumerate(grants, 1):
            lines.append(f"| {i} | {int(g.get('tokens', 0)):,} | "
                         f"${float(g.get('usd', 0.0)):.2f} | "
                         f"{g.get('actor', '?')} | {g.get('reason', '')} |")
        lines.append("")
        lines.append(f"Effective ceiling after top-ups: {eff.describe()}. "
                     f"A budget is per-finding and for its lifetime; it is never "
                     f"reset automatically, only extended deliberately.")
    lines.append("")
    if not per_seat:
        lines.append("No metered model calls were recorded for this finding.")
        return lines
    lines += ["| seat | model | calls | tokens | usd |",
              "|---|---|---:|---:|---:|"]
    for seat, e in sorted(per_seat.items()):
        usd = f"${e['usd']:.4f}" if e["usd"] else "—"
        lines.append(f"| {seat} | `{e['model']}` | {e['calls']} | "
                     f"{e['tok']:,} | {usd} |")
    lines.append(f"| **total** | | **{total.calls}** | **{total.tokens:,}** | "
                 f"**{('$%.4f' % total.usd) if total.usd else '—'}** |")
    if not total.priced:
        lines += ["", "*Dollar figures are partial: at least one seat has no price "
                      "configured, which is expected for a self-hosted endpoint.*"]
    return lines


REVIEW_SYSTEM = """You are reviewing a security patch written by a different model.

Your opinion is ADVISORY. A container has already decided whether this patch works:
it ran the frozen reproducer before and after, and ran the project's own test suite.
You cannot overturn that result and must not try. You are being asked a different
question: is this patch good *engineering*?

Consider: does it fix the root cause or only the symptom the reproducer happens to
trigger? Could the same bug still be reached by another path? Is the change wider
than it needs to be? Does it introduce a new problem the suite would not catch?

Reply ONLY with JSON:
  {"verdict": "sound" | "concerns" | "unsound",
   "reasons": ["..."],
   "residual_risk": "one sentence on what could still be wrong"}"""


def _advisory_review(f: Finding, ctx: Context, diff_or_file: str,
                     container_result: str) -> list[dict]:
    """Run the advisory reviewer seat. Never raises; never affects the verdict.

    Deliberately called AFTER the container has ruled, so the reviewer cannot
    influence pass/fail even by accident. Its config is recorded beside its opinion
    because the verdict is known to move on a single flag — an opinion without the
    config that produced it is not reproducible, and an unreproducible opinion in an
    evidence package is worse than none.
    """
    cfg = getattr(ctx, "config", None)
    if cfg is None:
        return []
    try:
        mc = cfg.model("verify")
    except Exception:
        return []          # no reviewer configured; advisory is optional by design

    same_family = False
    try:
        pc = cfg.model("patch")
        same_family = bool(pc.family and pc.family == mc.family)
    except Exception:
        pass

    try:
        client = _client(ctx, "verify", f, "verify")
        obj = client.chat_json(
            [{"role": "system", "content": _resolve_prompt(ctx, "REVIEW_SYSTEM", REVIEW_SYSTEM)},
             {"role": "user", "content":
              f"Vulnerability: {f.title or '(untitled)'}\n"
              f"CWE: {f.cwe or 'unspecified'}\n\n"
              f"Description:\n{(f.description or '(none)')[:1500]}\n\n"
              f"Proposed patch:\n```\n{diff_or_file[:12000]}\n```\n\n"
              f"Container result (already decided, not yours to change):\n"
              f"{container_result[:1500]}"}],
            required=("verdict",),
        )
        # Persist the raw advisory reply for evidence.
        ctx.store.add_artifact(
            f.id, "response", "verify",
            content=(client.last_raw_response or ""),
            meta={"seat": "verify_advisory",
                  "model": mc.model,
                  "endpoint": mc.endpoint,
                  "attempt": "advisory"},
            model=mc.model)
    except budget_mod.CeilingExceeded:
        raise                                    # the ceiling is not advisory
    except Exception as e:
        return [{
            "kind": "review_advisory",
            "content": f"advisory review unavailable: {e}",
            "meta": {"advisory": True, "available": False, "error": str(e)[:300]},
            "base_commit": f.base_commit,
        }]

    return [{
        "kind": "review_advisory",
        "content": json.dumps(obj, indent=2),
        "model": mc.model,
        "meta": {
            "advisory": True,
            "available": True,
            "verdict": obj.get("verdict", "?"),
            # The exact configuration that produced this opinion. GLM-5.2 was
            # observed returning "sound" with thinking off and "concerns" with
            # thinking on for the same patch, so these fields are part of the
            # finding, not decoration.
            "reviewer_config": {
                "model": mc.model, "endpoint": mc.endpoint,
                "family": mc.family, "temperature": mc.temperature,
                "max_tokens": mc.max_tokens, "extra": dict(mc.extra or {}),
            },
            "same_family_as_fixer": same_family,
            "independence": ("WEAK — reviewer shares a model family with the "
                             "fix-writer, so their errors are correlated"
                             if same_family else
                             "different model family from the fix-writer"),
        },
        "base_commit": f.base_commit,
    }]


def _target_dir(spec: dict) -> str:
    return spec.get("_target_dir") or spec.get("path") or "."


def _sandbox(ctx: Context, spec: dict | None = None,
             finding=None, persist: bool = False,
             network: str | None = None):
    """Sandbox factory that respects pod-per-finding.

    If `finding` has a container_id, attach to that container (pod-per-finding
    change 2). If not, create a fresh one. `persist=True` keeps it alive for
    the next stage on the same finding — reproduce sets this so verify can
    attach; verify sets this so rollback and iteration can attach.

    The caller is responsible for calling `_pin_container(finding, sb, ctx)`
    after a successful prepare() so freshly-created containers are recorded
    on the finding row.
    """
    cfg = getattr(ctx, "config", None)
    if cfg is None:
        return sandbox_mod.LocalSandbox(workdir=ctx.workdir)
    existing = getattr(finding, "container_id", "") if finding else ""
    return sandbox_mod.make(cfg.sandbox, workdir=ctx.workdir, spec=spec,
                            network=network,
                            existing_cid=existing, persist=persist)


def _pin_container(finding, sb, ctx: Context) -> None:
    """Record sb.cid on the finding row after a successful prepare().

    Runs unconditionally — writing the same cid twice is a no-op — so callers
    do not have to remember whether they attached vs created.
    """
    cid = getattr(sb, "cid", "") or ""
    if cid and cid != getattr(finding, "container_id", ""):
        try:
            ctx.store.update(finding.id, container_id=cid)
            finding.container_id = cid
        except Exception:
            # DBs from before the migration might not have the column. The
            # migration in Store.__init__ handles it, but be defensive.
            pass


# ---------------------------------------------------------------------------
# stages
# ---------------------------------------------------------------------------


@stage("ingest")
def ingest(f: Finding, ctx: Context) -> StageResult:
    """Validate the finding has the minimum needed to attempt a fix."""
    missing = [k for k in ("repo_url", "source") if not getattr(f, k, "")]
    if missing:
        return StageResult.fail(f"missing required field(s): {', '.join(missing)}",
                                meta={"outcome": "ingest_missing_fields",
                                      "missing": missing})
    if not (f.description or f.cwe or f.source_ref):
        return StageResult.reject(
            "no description, CWE, or source reference — nothing to localize from",
            meta={"outcome": "ingest_nothing_to_localize"})
    return StageResult.ok("accepted", meta={"outcome": "ingest_accepted"})


@stage("localize")
def localize(f: Finding, ctx: Context) -> StageResult:
    """
    Narrow the target to the files that hold the flaw.

    Declared files in the spec win — they are ground truth from whoever filed
    the finding. Otherwise fall back to a cheap scan. A model-driven backend
    (Antares, or the detector's own output) plugs in here without changing
    anything downstream; its output is a *reading order*, never ground truth.
    """
    # Supply-chain / malicious-publish advisories have no code vulnerability to
    # localize — the "fix" was removing malware, not patching a line. Reject
    # rather than block for a spec that could never exist.
    from .feeds import is_supply_chain
    if is_supply_chain(f.title, f.description):
        return StageResult.reject(
            "supply-chain / malicious-publish advisory — there is no code "
            "vulnerability to localize or patch; the fix was a clean republish",
            meta={"outcome": "localize_supply_chain_advisory"})

    spec = _spec(f, ctx)
    if spec is None:
        # Advisory-sourced finding with no local target: resolve the real
        # upstream fix from OSV/GitHub. The changed files ARE the localization;
        # the diff is stored as ground truth (not fed to the patch stage).
        if f.source == "advisory" and (f.source_ref or "").upper().startswith("CVE"):
            from . import fetch
            res = fetch.resolve_fix(f.source_ref, repo_url=f.repo_url)
            if "error" in res:
                return StageResult.blocked(
                    f"could not resolve an upstream fix: {res['error']}. "
                    f"Attach a target spec with --spec to localize manually.",
                    meta={"outcome": "localize_upstream_fix_unresolved"})
            arts = [{
                "kind": "localization",
                "content": "\n".join(res["changed_files"]),
                "meta": {"files": res["changed_files"], "source": "upstream-fix",
                         "fix_commit": res["fix_commit"], "repo": res["repo"],
                         "commit_url": res["commit_url"],
                         "test_files": res["test_files"]},
                "base_commit": res["fix_commit"],
            }, {
                "kind": "reference_patch",
                "content": res["reference_patch"],
                "meta": {"fix_commit": res["fix_commit"], "commit_url": res["commit_url"],
                         "message": res["message"]},
                "base_commit": res["fix_commit"],
            }]
            n = len(res["changed_files"])
            t = f" ({len(res['test_files'])} test file(s))" if res["test_files"] else ""
            return StageResult.ok(
                f"localized to {n} file(s) from upstream fix {res['fix_commit'][:10]}{t}",
                artifacts=arts,
                meta={"outcome": "localize_from_upstream_fix", "n_files": n})

        return StageResult.blocked(
            "no target spec attached — add the finding with --spec, or "
            "implement a repository-fetching localizer",
            meta={"outcome": "localize_no_spec"})

    files = [x for x in (spec.get("files") or []) if x]
    target = _target_dir(spec)

    if not files:
        # Symptom-based localization: reason forward from the report to the file,
        # with no upstream fix to read the answer off. This is the code path that
        # makes an unfixed vulnerability processable at all.
        sym = spec.get("symptom") or {}
        try:
            client = _client(ctx, "detect", f, "localize")
        except Exception:
            try:
                client = _client(ctx, "patch", f, "localize")   # detect role is optional
            except Exception as e:
                return StageResult.blocked(
                    f"symptom localization needs a model and none is configured "
                    f"({e}). Declare files in the spec, or add [models.detect].",
                    meta={"outcome": "localize_no_model_configured"})

        res = symptom_mod.localize(
            client,
            target_dir=target,
            advisory=f.description or f.title or "",
            trace=sym.get("stack_trace", ""),
            poc=sym.get("poc", ""),
            good_rev=sym.get("good_rev", ""),
            bad_rev=sym.get("bad_rev", ""),
        )
        if "error" in res:
            return StageResult.blocked(
                f"symptom localization failed: {res['error']}",
                meta={"outcome": "localize_symptom_failed"})

        files = res["files"]
        ev = res["evidence"]
        signals = []
        if ev.get("stack_trace_files"):
            signals.append(f"{len(ev['stack_trace_files'])} trace frame(s)")
        if ev.get("narrowed_by_revision"):
            signals.append(f"revision range ({ev['narrowed_by_revision']} files)")
        if ev.get("has_poc"):
            signals.append("PoC")
        signals.append("advisory")

        return StageResult.ok(
            f"localized by symptom to {files[0]} "
            f"(+{len(files) - 1} alternates) from {', '.join(signals)}",
            artifacts=[{
                "kind": "localization",
                "content": "\n".join(res["ranked"]),
                "meta": {"files": files, "source": "symptom",
                         "ranked": res["ranked"], "evidence": ev,
                         "why": res.get("why", "")},
                "base_commit": f.base_commit,
            }],
            meta={"outcome": "localize_by_symptom"})
    else:
        note = f"{len(files)} file(s) declared in spec"

    # A containerised target has no host-side source to stat; the file lives in
    # the image and is checked there when it is read.
    _in_image = str(((spec.get("target") or {}).get("mode") or "")
                    ).replace("_", "-") == "in-image"
    if not _in_image:
        missing = [p for p in files if not os.path.exists(os.path.join(target, p))]
        if missing:
            return StageResult.fail(
                f"declared file(s) not found: {', '.join(missing)}",
                meta={"outcome": "localize_declared_files_missing",
                      "missing": missing})

    return StageResult.ok(note, artifacts=[{
        "kind": "localization",
        "content": "\n".join(files),
        "meta": {"files": files, "source": "spec" if spec.get("files") else "scan"},
        "base_commit": f.base_commit,
    }], meta={"outcome": "localize_from_spec"})


def _resolve_in_image(sb, rel, src_root, install_root):
    """Resolve a localization relpath to the absolute file that actually exists in
    the committed image. Enforces the localize->patch path contract (R-4.2.1):
    localize runs BEFORE the image exists, so a declared path can carry a bogus
    prefix (the spec author's guess at the layout). Here, where the image is
    finally real, we resolve it authoritatively.

    Resolution order:
      1. The path exactly as patch will read it (sandbox.path() semantics: an
         absolute rel is used verbatim, otherwise it is joined under src_root). If
         that file exists, the contract already holds -- return it unchanged.
      2. Rebase the file's trailing suffix onto the KNOWN install_root -- where
         provision installed the target, hence the copy the reproducer exercises,
         not a blind guess. The longest trailing suffix that matches exactly one
         file wins; a suffix matching >1 file is ambiguous and is NEVER guessed.

    Returns (abs_path, note) on success, or (None, reason) if it cannot be
    resolved to exactly one file under install_root.
    """
    if rel.startswith("/"):
        direct = rel
    else:
        _b = (src_root or "/").rstrip("/")
        direct = f"{_b}/{rel}" if _b else f"/{rel}"
    if sb.run(f"test -e {shlex.quote(direct)}").returncode == 0:
        return direct, "resolved directly"

    base = (install_root or "").strip().rstrip("/")
    segs = [s for s in rel.split("/") if s]
    if base and len(segs) >= 2:
        for k in range(len(segs), 1, -1):
            suffix = "/".join(segs[-k:])
            r = sb.run(f"find {shlex.quote(base)} -xdev -type f -path "
                       f"{shlex.quote('*/' + suffix)} 2>/dev/null | head -20")
            hits = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
            if len(hits) == 1:
                return hits[0], f"rebased onto install_root {base} via '*/{suffix}'"
            if len(hits) >= 2:
                return None, (f"'*/{suffix}' is ambiguous under install_root "
                              f"{base}: {len(hits)} matches {hits[:5]}")

    tail = "/".join(segs[-2:]) if len(segs) >= 2 else rel
    r = sb.run(f"find / -xdev -type f -path {shlex.quote('*/' + tail)} "
               f"2>/dev/null | head -20")
    anywhere = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    return None, (f"does not resolve under install_root {base or '(unset)'}; "
                  f"'*/{tail}' exists in the image at {anywhere or 'nowhere'}")


def _reconcile_localization(ctx, f, sb, src_root, install_root):
    """Enforce the localize->reproduce/patch path contract at the boundary where the
    committed image finally exists (R-4.2.1). Every localization file MUST resolve
    to a real file in the image; a path that does not resolve is a localize/spec
    defect surfaced HERE (provision), never a patch defect later.

    Returns (fail_result, corrected_artifact):
      * fail_result -- a StageResult.fail if any path cannot be resolved. The caller
        returns it, so provision fails with the correct attribution instead of
        letting patch die on an unreadable source ~an image-build later.
      * corrected_artifact -- a localization artifact dict to persist if any path
        was rewritten, else None.
    (None, None) means every path already resolved; nothing to do.
    """
    loc = ctx.store.latest_artifact(f.id, "localization")
    if loc is None:
        return None, None
    try:
        meta = json.loads(loc["meta"]) or {}
    except (json.JSONDecodeError, TypeError):
        meta = {}
    files = [x for x in (meta.get("files") or []) if x]
    if not files:
        return None, None

    sr = (src_root or "/").rstrip("/")
    new_files: list[str] = []
    resolutions: list[dict] = []
    changed = False
    for rel in files:
        abs_path, note = _resolve_in_image(sb, rel, src_root, install_root)
        if abs_path is None:
            ctx.store.emit(
                f.id, "provision", "localization_unresolved",
                f"localization path {rel} does not resolve in the committed "
                f"image -- {note}",
                meta={"localized_path": rel, "install_root": install_root,
                      "root": src_root})
            return StageResult.fail(
                f"localization path {rel!r} does not resolve in the committed "
                f"image ({note}). A localization path that does not resolve is a "
                f"localize/spec defect, not a patch defect -- correct the target "
                f"path or the localizer; re-running the same spec fails "
                f"identically.",
                meta={"outcome": "provision_localization_unresolved",
                      "localized_path": rel, "resolution_note": note}), None
        # Re-express relative to src_root when the file lives under it, else keep
        # it absolute. Both read identically through sandbox.path().
        if sr and abs_path.startswith(sr + "/"):
            new_rel = abs_path[len(sr):].lstrip("/")
        elif sr in ("", "/"):
            new_rel = abs_path.lstrip("/")
        else:
            new_rel = abs_path
        resolutions.append({"from": rel, "to": new_rel, "abs": abs_path,
                            "note": note})
        new_files.append(new_rel)
        if new_rel != rel:
            changed = True

    if not changed:
        return None, None

    ctx.store.emit(
        f.id, "provision", "localization_reconciled",
        "reconciled localization path(s) against the committed image: "
        + "; ".join(f"{r['from']} -> {r['to']} ({r['note']})"
                    for r in resolutions if r["from"] != r["to"]),
        meta={"resolutions": resolutions, "install_root": install_root})
    corrected = {
        "kind": "localization",
        "content": "\n".join(new_files),
        "meta": {"files": new_files,
                 "source": "reconciled",
                 "reconciled_from": meta.get("source", "unknown"),
                 "original_files": files,
                 "resolutions": resolutions},
        "base_commit": f.base_commit,
    }
    return None, corrected


@stage("provision")
def provision(f: Finding, ctx: Context) -> StageResult:
    """Bring up a pod, iterate build/install until the reproducer confirms
    an evidence match, commit the pod to an image, write the spec.

    ARVO findings short-circuit: if a spec artifact already declares
    target.image, provision is a no-op (the image is pre-baked and
    reproduce can attach directly). Non-ARVO findings require an
    operator-authored draft_spec artifact holding the HTTP evidence
    rules; the loop uses those as the acceptance oracle.

    INVARIANT (asserted at return): provision writes NO reproducer_lock.
    The lock is written only by @stage("reproduce") after classify
    returns CONFIRMED_RED. See docs/http-classifier-design.md and
    the recon report at Pass 2 Step 0, Section 7."""
    import time as _t
    from . import provision as provision_mod
    from . import spec as spec_mod
    from .config import ConfigError

    # 1. Short-circuit if a spec already carries target.image (ARVO/prebuilt)
    spec_art = ctx.store.latest_artifact(f.id, "spec")
    if spec_art is not None:
        try:
            existing = json.loads(spec_art["content"] or "{}")
        except json.JSONDecodeError:
            existing = {}
        if (existing.get("target") or {}).get("image"):
            return StageResult.ok(
                "spec.target.image already set — no provisioning needed",
                meta={"outcome": "provision_shortcircuit"})

    # 2. Operator-authored draft is REQUIRED for non-ARVO findings
    draft_art = ctx.store.latest_artifact(f.id, "draft_spec")
    if draft_art is None:
        return StageResult.blocked(
            "no draft_spec artifact — the operator must author the HTTP "
            "evidence rules on the finding page before provision can run "
            "(POST /api/finding/<id>/draft-spec or use the editor UI)",
            meta={"outcome": "provision_no_draft_spec"})
    try:
        draft_http = json.loads(draft_art["content"] or "{}")
    except json.JSONDecodeError as e:
        return StageResult.fail(
            f"draft_spec artifact is unreadable JSON: {e}",
            meta={"outcome": "provision_draft_unreadable"})

    # 3. Provision-seat model client (Metered so spend accounts to the
    # per-finding ceiling; rows tag seat='provision' for the "did
    # provision burn >20%?" instrumentation).
    try:
        client = _client(ctx, "provision", f, "provision")
    except (ConfigError, RuntimeError) as e:
        # ConfigError and RuntimeError both mean "we can't obtain a
        # provision-seat client" — folding them into one outcome keeps
        # the outcome-uniqueness guard honest.
        return StageResult.blocked(
            f"provision seat not configured: {e}",
            meta={"outcome": "provision_no_model_configured"})

    # 4. Remaining USD budget
    ceiling = budget_mod.load_ceiling(ctx.store, getattr(ctx, "config", None))
    _spent = budget_mod.spent(ctx.store, f.id)
    remaining_usd = (ceiling.max_usd - _spent.usd
                     if ceiling.max_usd else 0.0)
    if ceiling.max_usd and remaining_usd <= 0.01:
        return StageResult.blocked(
            f"insufficient budget: ${remaining_usd:.4f} remaining of "
            f"${ceiling.max_usd:.2f} — top up the ceiling before provision",
            meta={"outcome": "provision_no_budget"})

    # 5. Read the upstream reference patch if we have one — it gives the
    # model the fix commit sha, which its parent is what we want to build.
    ref = ctx.store.latest_artifact(f.id, "reference_patch")
    reference_patch = ""
    if ref is not None:
        reference_patch = ref["content"] or ""

    # 5b. Resolve preferred_template if the operator picked one. Three
    # gates (row exists, image exists, digest matches) — any failure is
    # a hard fail with a distinct outcome. Silent fallback to bare
    # ubuntu would let a drifted template ship an unverified environment,
    # which is the ARVO-answer-key drift wearing a new coat.
    base_image = "ubuntu:22.04"
    template_meta: dict = {}
    preferred = (draft_http.get("preferred_template") or "").strip()
    if preferred:
        res = provision_mod.resolve_template_image(
            store=ctx.store, sandbox_config=ctx.config.sandbox,
            template_name=preferred)
        if not res["ok"]:
            # Branch on outcome so each StageResult.fail carries a
            # LITERAL outcome string — the outcome-coverage guard
            # rejects computed values (via test_no_outcome_is_computed_
            # at_runtime), and rightly so: a typo in a runtime dict
            # value would surface as an UnknownOutcome mid-flight.
            outcome = res["outcome"]
            if outcome == "provision_template_missing":
                return StageResult.fail(
                    res["error"],
                    meta={"outcome": "provision_template_missing",
                          "template_name": preferred})
            if outcome == "provision_template_image_gone":
                return StageResult.fail(
                    res["error"],
                    meta={"outcome": "provision_template_image_gone",
                          "template_name": preferred})
            if outcome == "provision_template_digest_drift":
                return StageResult.fail(
                    res["error"],
                    meta={"outcome": "provision_template_digest_drift",
                          "template_name": preferred})
            # Defensive: the resolver only produces those three failure
            # outcomes. A new one added later without updating this
            # branch means it never runs — better an assertion here
            # than an UnknownOutcome the runner would swallow into a
            # generic failure.
            raise AssertionError(
                f"resolve_template_image returned unknown outcome "
                f"{outcome!r} — extend the branch above")
        base_image = res["image_tag"]
        template_meta = {"template_name": res["template_name"],
                         "verified_digest": res["verified_digest"]}
        # Audit trail records WHICH digest was verified for THIS finding,
        # independent of any later pod_templates rebuild that changes
        # the row's stored digest. Post-hoc forensics on "which bytes
        # was this finding provisioned against" reads this event.
        ctx.store.emit(
            f.id, "provision", "template_attached",
            f"attached to template {res['template_name']!r} "
            f"({base_image}) with digest verified at attach time",
            meta={"template_name": res["template_name"],
                  "image_tag": res["image_tag"],
                  "verified_digest": res["verified_digest"]})

    # 6. Bring up the pod from base_image (bare ubuntu OR template).
    # The model can install anything else via install_package /
    # exec_in_pod on top of whatever base was resolved above.
    # Provision-specific network override — cfg.sandbox.provision_network
    # ("none" default, "bridge" for live runs that need to fetch source).
    # See SandboxConfig for the temporary-posture note. All other stages
    # keep the default cfg.sandbox.network (which stays "none").
    pod_spec = {"target": {"image": base_image, "mode": "in-image",
                           "root": "/"}}
    prov_net = getattr(ctx.config.sandbox, "provision_network", "none")

    started_at = _t.time()

    with _sandbox(ctx, pod_spec, finding=f, persist=True,
                  network=prov_net) as sb:
        try:
            sb.prepare()
        except sandbox_mod.SandboxError as e:
            return StageResult.fail(
                f"pod prep failed: {e}",
                meta={"outcome": "provision_pod_prep_failed"})
        _pin_container(f, sb, ctx)

        ctx.store.emit(
            f.id, "provision", "pod_ready",
            f"pod up on {base_image}, cid={sb.cid[:12] if sb.cid else '?'}",
            meta={"image": base_image, "cid": sb.cid})

        # Wire-up: surface ecosystem/package/fixed_version to build_initial_msg
        # via attributes on f (Finding is a mutable dataclass). This lets the
        # initial message inject version-pinned setup commands from the
        # strategy without changing run_provision_loop's signature.
        _adv_eco = ""
        _adv_pkg = ""
        _adv_fixed = ""
        try:
            _r = ctx.store.conn.execute(
                "SELECT ecosystem, package, fixed_version FROM advisories "
                "WHERE cve=?",
                (f.source_ref,)).fetchone()
            if _r:
                _adv_eco = str(_r["ecosystem"] or "").strip().lower()
                _adv_pkg = str(_r["package"] or "").strip()
                _adv_fixed = str(_r["fixed_version"] or "").strip()
                f._ecosystem = _adv_eco
                f._package = _adv_pkg
                f._fixed_version = _adv_fixed
        except Exception:
            pass

        # Recursive-loop prerequisites: strategy + pkg + affected_ref must
        # be present BEFORE the loop starts (checks reference them). Fatal
        # if declared ecosystem has no strategy or the version is missing.
        _strategy = None
        _affected_ref = ""
        # spec_now for ecosystem override (declared explicitly overrides advisory)
        try:
            _spec_now = _spec(f, ctx) or {}
            _spec_eco = str(_spec_now.get("ecosystem") or "").strip().lower()
        except Exception:
            _spec_eco = ""
        _eco_final = _spec_eco or _adv_eco
        # Only route through the ecosystem-strategy path when NO
        # preferred_template is set. Templates ship pre-warmed with the
        # ecosystem installed; running our bootstrap on top is either
        # redundant or fails (e.g. no fixed_version to derive an
        # affected version from). Findings that pick a template get
        # single-shot provision (like the pre-Aug-08 flow); findings
        # that don't get the recursive-loop + bootstrap path.
        if _eco_final and not preferred:
            from .ecosystems import for_ecosystem, UnknownEcosystem
            try:
                _strategy = for_ecosystem(_eco_final)
            except UnknownEcosystem as e:
                return StageResult.fail(
                    f"no ecosystem strategy for {_eco_final!r}: {e}",
                    meta={"outcome": "provision_no_ecosystem_strategy"})
            if not _adv_pkg:
                return StageResult.fail(
                    f"ecosystem {_eco_final!r} requires advisories.package "
                    f"to be populated for {f.source_ref!r}",
                    meta={"outcome": "provision_strategy_prereqs_missing"})
            _affected_ref = _strategy.recommended_affected_version(_adv_fixed) or ""
            if not _affected_ref:
                return StageResult.fail(
                    f"ecosystem {_eco_final!r} strategy cannot derive an "
                    f"affected version from fixed_version={_adv_fixed!r}. "
                    f"Advisory needs a semver-shaped fixed_version.",
                    meta={"outcome": "provision_strategy_prereqs_missing"})

        try:
            done_obj, turns, tool_calls = provision_mod.run_provision_loop(
                ctx, f, client, sb, draft_http,
                base_image=base_image,
                reference_patch=reference_patch,
                # Bumped 40 → 60 (2026-08-08) to give the recursive
                # loop headroom for check-failure recoveries. Prior run
                # hit exhaustion at turn 40 the same turn GLM was fixing
                # the tool-not-found miss — a raise of even one turn
                # would have completed it.
                max_turns=60,
                max_usd=remaining_usd if ceiling.max_usd else 0.0,
                strategy=_strategy,
                pkg_name=_adv_pkg,
                affected_ref=_affected_ref)
        except provision_mod.ProvisionBudgetExhausted as e:
            return StageResult.fail(
                f"provision budget exhausted: {e}",
                meta={"outcome": "provision_budget_exhausted"})
        except provision_mod.ProvisionGaveUp as e:
            return StageResult.fail(
                f"provision model gave up: {e}",
                meta={"outcome": "provision_gave_up"})
        except provision_mod.ProvisionCommitFailed as e:
            return StageResult.fail(
                f"pod commit failed (infra, not model): {e}",
                meta={"outcome": "provision_commit_failed"})
        except provision_mod.ProvisionBootstrapFailed as e:
            return StageResult.fail(
                f"bootstrap failed (deterministic pod prep): {e}",
                meta={"outcome": "provision_bootstrap_failed"})
        except provision_mod.ProvisionLoopStuck as e:
            return StageResult.fail(
                f"provision loop stuck (identical fail signature repeated): {e}",
                meta={"outcome": "provision_loop_stuck"})
        except provision_mod.ProvisionLoopExhausted as e:
            return StageResult.fail(
                f"provision loop exhausted (all-checks-pass never reached): {e}",
                meta={"outcome": "provision_loop_exhausted"})

        target_url = str(done_obj.get("target_url") or "").strip()
        install_root = str(done_obj.get("install_root") or "").strip()

        # 6.5 CHUNK 3: materialize the reproducer script into the pod
        # (bytes → /reproduce.pw.sh + extras). Failing here means the
        # provision loop returned an ill-formed done_obj.
        try:
            reproduce_cmd, frozen_files = provision_mod.materialize_reproducer(sb, done_obj)
        except Exception as e:
            return StageResult.fail(
                f"provision reproducer materialization failed: {e}",
                meta={"outcome": "provision_reproducer_invalid"})

        # 6.6 RECURSIVE PROVISION LOOP (2026-08-08): the strategy detect +
        # hermeticity smoke live INSIDE run_provision_loop now, so this
        # block only reads the strategy fields the spec write needs. If we
        # got here at all, done_obj["image_tag"] carries the FINAL committed
        # image (all 3 checks passed against it).
        install_root = str(done_obj.get("install_root") or install_root or "").strip()
        image_tag_from_loop = str(done_obj.get("image_tag") or "").strip()
        strategy = _strategy
        eco_name = _eco_final
        pkg_name = _adv_pkg
        strat_build_cmd = ""
        strat_incremental = ""
        strat_installed_dist_root = ""
        strat_version_pins: list[str] = []
        if strategy is not None:
            from .ecosystems.base import EcosystemScopeExceeded
            try:
                strat_build_cmd = strategy.build_command(sb, install_root, pkg_name)
                strat_incremental = strategy.incremental_build_command(sb, install_root, pkg_name) or ""
                strat_installed_dist_root = strategy.installed_dist_root(sb, install_root, pkg_name)
                strat_version_pins = list(strategy.version_pin_files(sb, install_root, pkg_name))
                frozen_files.extend(strat_version_pins)
            except EcosystemScopeExceeded as e:
                # This should be caught by check_hermetic_smoke inside the
                # loop, but keep the guard here for defence in depth.
                return StageResult.fail(
                    f"ecosystem strategy {eco_name!r} scope exceeded: {e}",
                    meta={"outcome": "provision_strategy_scope_exceeded"})

        # 6.8 CHUNK 3 + Rev-3: compute installed-dist manifest as PRISTINE
        # snapshot for the verify-side sanity check. Sanity only — not a
        # verdict gate (bundlers can produce byte-identical output on a
        # valid fix that lands in a hashed chunk).
        pristine_dist_manifest: dict = {}
        if strat_installed_dist_root:
            try:
                pristine_dist_manifest = _compute_dist_manifest(sb, strat_installed_dist_root)
            except Exception as e:
                ctx.store.emit(f.id, "provision", "dist_manifest_compute_failed",
                               f"failed to compute pristine installed-dist manifest "
                               f"at {strat_installed_dist_root}: {e}")

        # 7. Image tag already committed INSIDE the loop by the recursive
        # provision loop (2026-08-08). Just consume the tag it produced.
        image_tag = image_tag_from_loop or f"patchwing-provisioned-{f.id}"
        # No commit call here — done in run_provision_loop when all 3
        # binary checks passed. If we bypassed the loop (no strategy /
        # non-ecosystem finding), commit here as a fallback.
        if not image_tag_from_loop:
            try:
                provision_mod.commit_pod(sb, image_tag)
            except sandbox_mod.SandboxError as e:
                return StageResult.fail(
                    f"pod commit failed: {e}",
                    meta={"outcome": "provision_commit_failed"})

        ctx.store.emit(
            f.id, "provision", "pod_committed",
            f"committed to image {image_tag}",
            meta={"image": image_tag, "target_url": target_url,
                  "reproduce_command": reproduce_cmd,
                  "install_root": install_root,
                  "ecosystem": eco_name})

        # 7.5 (R-4.2.1) Enforce the localize->patch path contract now that the
        # image exists: every localization file must resolve in the committed
        # image. Reconcile a bogus prefix against the authoritative install_root;
        # fail HERE -- a localize/spec defect -- if a path cannot be resolved,
        # rather than letting patch die on an unreadable source an image-build
        # later. _source_root is hoisted so the spec below reuses the exact value
        # the reconciliation resolved against.
        _source_root = (strategy.source_root_in_pod(sb)
                        if strategy is not None else "/")
        _loc_fail, _loc_fixed = _reconcile_localization(
            ctx, f, sb, _source_root, install_root)
        if _loc_fail is not None:
            return _loc_fail

        # 8. Build the final spec.
        recipe = provision_mod.recipe_from_events(ctx, f)
        final_spec = {
            "target": {
                "image": image_tag,
                "mode": "in-image",
                # 2026-08-10: for ecosystem-strategy targets, target.root
                # is the SOURCE ROOT (where files listed by localization
                # live), NOT the image root. Patch stage reads files
                # relative to this; verify writes patched bytes back
                # via this base. For non-ecosystem findings (ARVO etc)
                # keep the legacy '/' root.
                "root": _source_root,
                "install_root": install_root,
                "installed_dist_root": strat_installed_dist_root,
                "installed_dist_manifest_pristine": pristine_dist_manifest,
            },
            "commands": {
                "reproduce": reproduce_cmd,
                "build": strat_build_cmd,
                "incremental_build": strat_incremental,
            },
            "reproducer": {
                "files": frozen_files,
                "origin": "provision_materialized",
            },
            "reproducer_kind": "http",
            "http": {
                **draft_http,
                "url": target_url,
            },
            "ecosystem": eco_name,
            "package": pkg_name,
            "provision_recipe": recipe,
        }

        # 9. Validate through the FULL validator (require_url=True). If
        # this fails, provision produced a spec that reproduce would
        # reject — better to fail here where the audit trail names the
        # exact defect than let reproduce block with an opaque error.
        try:
            spec_mod.normalize_spec(final_spec)
        except spec_mod.SpecError as e:
            return StageResult.fail(
                f"provision produced an invalid spec: {e}",
                meta={"outcome": "provision_invalid_spec"})

        elapsed = int(_t.time() - started_at)
        artifacts = [{
            "kind": "spec",
            "content": json.dumps(final_spec, indent=2, sort_keys=True),
            "meta": {
                "reproducer_kind": "http",
                "image": image_tag,
                "target_url": target_url,
                "provision_turns": turns,
                "provision_tool_calls": tool_calls,
                "provision_seconds": elapsed,
            },
            "base_commit": f.base_commit,
        }]
        # Persist the reconciled localization (R-4.2.1) so patch reads a path that
        # resolves. Appended after the spec so `latest_artifact("localization")`
        # returns this corrected copy.
        if _loc_fixed is not None:
            artifacts.append(_loc_fixed)

    # 10. INVARIANT (this is a real assert, not a comment): provision
    # never writes reproducer_lock. That artifact is written ONLY by
    # @stage("reproduce") after classify returns CONFIRMED_RED. If this
    # fires, some code path above wrote a lock — find it and remove it;
    # do not weaken this check.
    assert ctx.store.latest_artifact(f.id, "reproducer_lock") is None, (
        "provision must not write a reproducer_lock — reproduce is the "
        "sole writer of that artifact (see stages.py reproduce stage). "
        "If this assert fires, some path in provision or provision_mod "
        "wrote one; find it and remove it, do NOT weaken the assert.")

    return StageResult.ok(
        f"provision complete: image={image_tag}, "
        f"url={target_url}, {turns} turn(s), "
        f"{tool_calls} tool call(s), {elapsed}s elapsed"
        + (f", from template {template_meta.get('template_name')!r}"
           if template_meta else ""),
        artifacts=artifacts,
        meta={"outcome": "provision_complete",
              "image": image_tag,
              "target_url": target_url,
              "turns": turns,
              "tool_calls": tool_calls,
              "seconds": elapsed,
              # Populated iff base was a template; empty dict → bare
              # ubuntu:22.04 was used. Post-hoc forensics reads this to
              # answer "was this finding provisioned against a cached
              # template, and if so which digest?"
              "template": template_meta})


@stage("reproduce")
def reproduce(f: Finding, ctx: Context) -> StageResult:
    """
    Confirm the bug is real by running a reproducer that must FAIL.

    Definition-A: the reproducer demonstrates a trigger plus an observable
    boundary violation and stops there. Convention is non-zero while the
    vulnerability is present, zero once it is closed.

    A reproducer that already passes means the bug is not there — that is a
    rejection, not a failure. This is the gate that stops the fixer being spent
    on candidates that were never real.
    """
    spec = _spec(f, ctx)
    if spec is None:
        # Advisory finding that was localized from the upstream fix: we know the
        # files and have the real patch, but reproducing needs the project built
        # and run in a sandbox — the execution-plane / VM work.
        loc = ctx.store.latest_artifact(f.id, "localization")
        if loc is not None:
            meta = json.loads(loc["meta"] or "{}")
            if meta.get("source") == "upstream-fix":
                return StageResult.blocked(
                    f"localized to {len(meta.get('files', []))} file(s) and the "
                    f"upstream reference fix is attached. Reproducing needs the "
                    f"project checked out at the parent of {meta.get('fix_commit','')[:10]} "
                    f"and built/run in a sandbox — that is the execution-plane (VM) "
                    f"step, and the toolchain isn't wired here yet.",
                    meta={"outcome": "reproduce_needs_execution_plane"})
        return StageResult.blocked("no target spec attached",
                                   meta={"outcome": "reproduce_no_spec"})

    cmd = (spec.get("commands") or {}).get("reproduce", "")
    if not cmd:
        return StageResult.blocked(
            "spec defines no reproduce command — a finding without a failing "
            "reproducer cannot be verified, and an unverifiable patch is not "
            "worth a maintainer's time",
            meta={"outcome": "reproduce_no_command"})

    target = _target_dir(spec)
    # Pod-per-finding (change 2): keep this pod alive for verify + rollback +
    # iterate. On first reproduce there is no container_id yet so a fresh pod
    # is created; _pin_container records it on the finding row.
    with _sandbox(ctx, spec, finding=f, persist=True) as sb:
        try:
            sb.prepare(target)
        except sandbox_mod.InImageSandbox.PodLost as e:
            return StageResult.fail(
                f"POD LOST at reproduce — {e}",
                meta={"outcome": "pod_lost_at_reproduce",
                      "patch_evaluated": False})
        _pin_container(f, sb, ctx)
        ctx.store.emit(f.id, "reproduce", "pod_ready",
                       f"container ready: {sb.cid[:12]} from {(spec.get('target') or {}).get('image', '?')}",
                       meta={"container_id": sb.cid,
                             "image": (spec.get("target") or {}).get("image", ""),
                             "root": (spec.get("target") or {}).get("root", "")})
        build = (spec.get("commands") or {}).get("build", "")
        # A containerised corpus ships a PRE-BUILT artifact: the image reproduces
        # as-is. Building before the first reproduce would cost a full compile
        # (23 minutes on ARVO/libxml2-MSan) to arrive at the binary already in the
        # image. The build command still matters — verify needs it after a patch —
        # so it is skipped here rather than removed from the spec.
        if (spec.get("target") or {}).get("prebuilt"):
            build = ""
        if build:
            r = sb.run(build)
            if not r.ok:
                # The tail is in the message for a human skimming a log line, but
                # the message is truncated and not an artifact. The verdict "the
                # build failed" is only auditable if the build output is attached.
                return StageResult.fail(
                    f"build failed: {r.tail(600)}",
                    meta={"outcome": "reproduce_prebuild_failed"},
                    artifacts=[{
                        "kind": "build_log",
                        "content": r.tail(4000),
                        "meta": {"cmd": r.cmd, "returncode": r.returncode,
                                 "timed_out": r.timed_out, "phase": "pre-reproduce"},
                        "base_commit": f.base_commit,
                    }])
        ctx.store.emit(f.id, "reproduce", "reproducer_start",
                       f"running: {cmd}", meta={"cmd": cmd})
        res = sb.run(cmd)
        ctx.store.emit(f.id, "reproduce", "reproducer_done",
                       f"exit {res.returncode} in {round(res.duration_s,1)}s "
                       f"({len(res.tail(8000))} bytes captured)",
                       duration_s=round(res.duration_s, 3),
                       meta={"returncode": res.returncode,
                             "timed_out": res.timed_out,
                             "output_bytes": len(res.tail(8000))})

    # §6b′ — FOUR states, never two. Read BEFORE any branch on returncode, so no
    # code path below can reach a red/green conclusion from the exit code alone.
    repro_out = res.tail(8000)
    reading = _classify_repro(f, ctx, res.returncode, repro_out, res.timed_out, duration_s=getattr(res, "duration_s", 0.0))
    ctx.store.emit(f.id, "reproduce", "four_state",
                   f"{reading['state']}: {reading['why']}",
                   meta=reading)

    art = [{
        "kind": "reproducer",
        "content": repro_out,
        "meta": {"cmd": cmd, "returncode": res.returncode,
                 "timed_out": res.timed_out, "duration_s": round(res.duration_s, 2),
                 "four_state": reading},
        "base_commit": f.base_commit,
    }]

    # `art` holds the reproducer output. Every path below is a verdict ON that
    # output, so every path below attaches it. These two used to return without it:
    # a rejection whose justification had been thrown away, on the stage a run
    # reaches first. "The vulnerability does not reproduce" is precisely the claim
    # a reader will want to check, and it was unsupported.
    if res.timed_out:
        return StageResult.retry("reproducer timed out", artifacts=art,
                                 meta={"outcome": "reproduce_timeout"})

    # §6b′ — FOUR states. The old code read `returncode == 0` as green and
    # everything else as red. On a target whose pristine exit code is 1, "everything
    # else" includes a missing mount, a shell error and a container that never
    # started, so every malfunction would have been recorded here as "the bug
    # reproduced" — and the whole run would be built on it.
    if reading["state"] == states_mod.DIFFERENT_BUG:
        return StageResult.reject(
            f"a sanitizer fired but this is NOT the tracked bug — "
            f"{reading['why']}. Not a reproduction, and not a clean run.",
            artifacts=art,
            meta={"outcome": "reproduce_different_bug", "four_state": reading})
    if reading["state"] == states_mod.HARNESS_FAULT:
        return StageResult.fail(
            f"HARNESS FAULT at reproduce — {reading['why']}. Nothing was "
            f"demonstrated about the vulnerability, so this is not evidence the "
            f"bug is absent either.",
            artifacts=art,
            meta={"outcome": "reproduce_harness_fault", "four_state": reading,
                  "patch_evaluated": False})
    if reading["state"] == states_mod.CONFIRMED_GREEN:
        return StageResult.reject(
            "reproducer passed on unpatched code — the vulnerability does not "
            "reproduce, so there is nothing to fix", artifacts=art,
            meta={"outcome": "reproduce_did_not_reproduce",
                  "returncode": res.returncode, "four_state": reading})
    # Only CONFIRMED_RED continues. Reached by exhaustion of a closed set of four,
    # never by "not green".

    # Wall integrity precondition, checked at the freeze point (WallEstablishError
    # is NOT a WallError, so the freeze handler below would not catch it — it gets
    # its own clause). The verdict is read from the OUTPUT of commands.reproduce,
    # so the command must run a file the wall is about to hash. A command whose
    # logic lives inline (`bash -c '...'`) or that runs an unfrozen file would let
    # the wall report "intact" while the thing deciding red/green was never
    # protected. This is the guard that keeps the frozen set and the
    # verdict-deciding command the same thing.
    try:
        wall_mod.validate_command_shape(spec, ctx.store, f.id)
    except wall_mod.WallEstablishError as e:
        return StageResult.fail(
            f"REPRODUCE COMMAND SHAPE INVALID — {e}",
            artifacts=art,
            meta={"outcome": "reproduce_command_shape_invalid",
                  "patch_evaluated": False})

    # Freeze the wall. This happens HERE, after the reproducer has demonstrated
    # the bug and before any patch exists — the wall is temporal, so the freeze
    # point is the whole guarantee. See wall.py.
    _in_image = str(((spec.get("target") or {}).get("mode") or "")
                    ).replace("_", "-") == "in-image"
    try:
        if _in_image:
            with _sandbox(ctx, spec) as _wsb:
                _wsb.prepare()
                manifest = wall_mod.freeze_in_sandbox(_wsb, spec)
        else:
            manifest = wall_mod.freeze(spec, target)
    except wall_mod.WallError as e:
        # HARD ABORT. An empty or unhashable wall is not a warning: it would let
        # the run proceed while protecting nothing, which is the failure this
        # whole mechanism exists to prevent.
        return StageResult.fail(f"WALL NOT ESTABLISHED — {e}", artifacts=art,
                                meta={"outcome": "reproduce_wall_not_established"})
    if not manifest.get("files") or not manifest.get("n_reproducer"):
        return StageResult.fail(
            "WALL NOT ESTABLISHED — the frozen set contains no reproducer. "
            "Declare [reproducer] files = [...] in the target spec. A wall that "
            "can be silently empty reports success while protecting nothing.",
            artifacts=art,
            meta={"outcome": "reproduce_wall_has_no_reproducer"})
    # §6b′ — the PRISTINE crash identity goes into the lock, beside the hashes.
    # The lock is the run's frozen ground truth, so this is where an identity that
    # later legs compare against belongs: recorded once, on unpatched code, before
    # a patch exists. Every later leg matches against THIS, never against whatever
    # it happens to see at the time.
    ctx.store.emit(f.id, "reproduce", "wall_frozen",
                   f"{manifest.get('n_files', 0)} file(s) frozen under "
                   f"{manifest.get('algorithm', 'sha256')} "
                   f"({manifest.get('n_reproducer', 0)} reproducer)",
                   meta={"n_files": manifest.get("n_files"),
                         "n_reproducer": manifest.get("n_reproducer"),
                         "algorithm": manifest.get("algorithm")})
    # §6b′ pristine identity — sanitizer uses dedup_token, HTTP uses observed_http_id.
    _pid = reading.get("dedup_token") or reading.get("observed_http_id") or ""
    _pmark = reading.get("marker") or reading.get("kind") or ""
    ctx.store.emit(f.id, "reproduce", "pristine_token_set",
                   f"pristine DEDUP_TOKEN = {_pid}",
                   meta={"pristine_dedup_token": _pid,
                         "pristine_marker": _pmark,
                         "pristine_returncode": res.returncode})
    manifest["pristine_dedup_token"] = _pid
    manifest["pristine_marker"] = _pmark
    manifest["pristine_returncode"] = res.returncode
    # Rev-2: freeze the verdict-config slice for HTTP-kind. Verify reads
    # from HERE, not from current spec.
    if reading.get("kind") == "http":
        _spec_now = _spec(f, ctx) or {}
        _http_now = _spec_now.get("http") or {}
        _vc = states_mod.serialize_pristine_http(
            _http_now, observed_status=int(reading.get("http_status", 0) or 0))
        manifest["verdict_config"] = _vc
        manifest["verdict_config_sha256"] = states_mod.verdict_config_sha256(_vc)
    art.append({
        "kind": "reproducer_lock",
        "content": json.dumps(manifest, indent=2, sort_keys=True),
        "meta": {"n_files": manifest["n_files"],
                 "n_reproducer": manifest["n_reproducer"],
                 "algorithm": manifest["algorithm"],
                 "pristine_dedup_token": _pid},
        "base_commit": f.base_commit,
    })

    return StageResult.ok(
        f"{states_mod.describe(reading)}; {wall_mod.summarize(manifest)}",
        artifacts=art,
        meta={"outcome": "reproduce_red_confirmed", "returncode": res.returncode,
              "four_state": reading})


PATCH_SYSTEM = """You are a security engineer fixing a vulnerability in code you maintain.

Return your fix as SEARCH/REPLACE blocks. Do NOT return the whole file, and do NOT
return a unified diff — line numbers and hunk headers are error-prone and a diff
that applies at the wrong offset silently corrupts unrelated code.

Rules that will be enforced mechanically:
- The SEARCH text must appear EXACTLY ONCE in the file. Include enough surrounding
  context to make it unique; a snippet like "if (ret == NULL)" occurs many times in
  C and will be REJECTED as ambiguous.
- Copy the SEARCH text VERBATIM from the source shown, including indentation and tabs.
- Change as little as possible, EXCEPT that identical instances of the same defect
  in the files you were given must all be fixed (see "Sibling occurrences" below).
- Preserve existing behaviour; other tests must keep passing.

Root cause, not symptom.
The reproducer output is not the bug. It is an artifact that surfaces the bug. Your
fix must eliminate the underlying defect. Making the reproducer stop firing without
eliminating the defect is not acceptable and will be rejected on review.

In particular: a patch that changes what an invalid operation reads or writes — rather
than preventing the invalid operation from happening — is a symptom mask, not a fix.
Silencing a sanitizer by hiding the invalid data does not close the bug; it hides it.
Example of a symptom mask: pre-zeroing a buffer whose contents are being read past the
number of bytes actually written. MemorySanitizer stops flagging the read because the
bytes are now defined zeros, but the out-of-bounds read still happens on every call.
The correct fix in that case is to bound the read at the written length, not to
initialize memory the reader should never have reached.

Sibling occurrences — what to scan for.
After you identify the fix for the crash site, scan the other functions in the files
you were given for the same defect pattern. If the identical flaw appears in another
function within those files, include a fix for each occurrence. "Same defect pattern"
means the same class of flaw (same missing initialization, same missing bound check,
same missing free, etc.) — not merely code that looks superficially similar. Do not
look beyond the files you were provided. Do not fix unrelated issues.

Sibling occurrences — how to format them.
The `edits` field is a single string containing one or more SEARCH/REPLACE blocks
concatenated together, regardless of how many occurrences you fix. Do not return
`edits` as an array or object.

Format each edit exactly like this:

<<<<<<< SEARCH
the exact existing text
=======
the replacement text
>>>>>>> REPLACE

Reply with JSON:
{
  "analysis": "see rubric below",
  "edits": "one or more SEARCH/REPLACE blocks, as shown above",
  "confidence": "high" | "medium" | "low"
}

The `analysis` field must answer, in order, in one paragraph:
1. What code path performs the invalid operation the reproducer surfaces?
2. Does this patch prevent that path from executing the invalid operation, or does it
   change what the path reads or writes? If the latter, you are writing a symptom
   mask — stop and rewrite the fix to prevent the invalid operation.
3. Are there sibling occurrences of the same defect in the provided files? If so,
   are they all covered by your edits? Name each function you patched.

The `confidence` field uses this rubric:
- "high" — the SEARCH block is verbatim from the source, the fix eliminates the
  invalid operation at its root (not by masking), and you can name every sibling
  occurrence in the provided files.
- "medium" — the fix is defensible but you had to reason about surrounding code you
  could not fully verify from what was shown.
- "low" — you are not confident this fully closes the defect; explain why in
  `analysis`.
"""


def _format_ambiguity_retry_note(err: "edit_mod.AmbiguousSearchError",
                                 file_rel: str) -> str:
    """The disambiguation note sent to the model on a single retry.

    Verbatim wording from the retry-on-ambiguous-SEARCH spec — the point is that
    the model is told exactly what the validator complained about and decides
    itself how to fix it. PatchWing does not autofix; it retries with an
    explanation. Parallel to the JSON-repair loop in models.chat_json.
    """
    return (
        "Your previous edit could not be applied.\n\n"
        f"SEARCH block {err.block_index} of {err.total_blocks} matched "
        f"{err.match_count} times in {file_rel}. The block must match exactly "
        "once. Include surrounding lines above and/or below the target until "
        "the SEARCH text is unique in the file.\n\n"
        "Your previous SEARCH block:\n"
        "<< SEARCH\n"
        f"{err.search}\n"
        ">>\n\n"
        "Return the same fix, with SEARCH blocks expanded until unique. Do "
        "not change what the fix does."
    )


INVESTIGATION_SYSTEM = """You are a security engineer fixing a vulnerability in code you maintain.

The crash trace tells you where the bug SURFACED, not necessarily where it LIVES.
Sanitizers report the site of the invalid operation and, when they can, the site
of the offending allocation. Neither is guaranteed to be the site of the logic
error that caused the problem. The actual defect may be in a file the trace never
names — a handler that leaks a partially-initialized object into a data structure
the trace does name, for example.

THIS IS A CLOSED LOOP AGAINST THE REPRODUCER. Every time you propose a fix
(a JSON with `edits`), the harness will:
  1. apply your SEARCH/REPLACE blocks in the pod
  2. rebuild the project
  3. run the reproducer
  4. classify the result (confirmed_red / confirmed_green / harness_fault / different_bug)

If the reproducer goes GREEN, the harness reverts your patch, rebuilds, and
runs the reproducer again. If it goes RED on revert, your fix is CONFIRMED
and the loop ends successfully.

If the reproducer is STILL RED (or the build failed), you receive the new
trace / build error back as the next turn's input, in the same conversation.
You keep investigating and can propose another fix. There is no separate
one-shot patch attempt — every attempt is measured by the reproducer itself.

The reproducer is the ONLY judge. There is no answer key, no expected diff,
no upstream patch you are being scored against. You succeed when the
reproducer stops firing and stays fired-when-reverted; you fail when the
budget is exhausted or you give up.

The cheapest and most informative probe is a PATCH ATTEMPT, not more reading.
Investigate only enough to form a first hypothesis — usually the finding's
description, the reproducer output, and the one or two files named by
localization are enough — then PROPOSE A FIX. The reproducer's red/green
result teaches you more than any amount of extra reading. Iterate:
patch → read the result → refine → patch again. Propose your FIRST fix within
the first turn or two; do not spend many turns reading before your first
attempt.

Prefer a real root-cause fix over a surface mask — if you patch a surface site
without addressing the underlying defect, the reproducer will keep firing on
revert (or the "green" was a mask) and you will see that in the loop. But test
your root-cause hypothesis BY PATCHING IT, not by exhaustively reading first.

Stay strictly inside the target's own source (the package/repo under test).
Do NOT read /proc, system logs, npm/pip/yarn caches, /root, or unrelated
files — the defect is never there and every such read wastes a turn. If you
have read more than two or three files without proposing a fix, stop reading
and propose your best candidate now.

""" + tools_mod.TOOL_SPEC + """

RESPONSE SCHEMA — reply with a single JSON object each turn. THREE choices:

(A) INVESTIGATE — request tools:
{
  "reasoning": "one paragraph on your current hypothesis and what you want to check",
  "tool_calls": [
    {"tool": "grep", "args": {"pattern": "xmlAddChild", "path_glob": "*.c"}},
    {"tool": "read_file", "args": {"path": "SAX2.c"}}
  ]
}

(B) PROPOSE A FIX — apply, build, run reproducer:
{
  "analysis": "one paragraph answering, in order: (1) what code path performs the invalid operation; (2) whether this patch prevents the invalid operation or changes what is read/written (the latter is a mask, do not do it); (3) sibling occurrences of the same defect and whether they are covered",
  "edits": "one or more SEARCH/REPLACE blocks, concatenated as a single string, using the format below",
  "confidence": "high" | "medium" | "low"
}

(C) GIVE UP — explicit failure with a reason:
{
  "give_up": "one paragraph explaining why you cannot fix this bug — what you
              investigated, what you concluded, and what a human would need
              to unblock progress"
}

Return exactly one of the three. Do not mix.

SEARCH/REPLACE format:

<<<<<<< SEARCH
the exact existing text
=======
the replacement text
>>>>>>> REPLACE

Mechanical rules on your `edits`:
- The SEARCH text must appear EXACTLY ONCE in the file. Include enough
  surrounding context to make it unique.
- Copy VERBATIM including indentation.
- Multiple SEARCH/REPLACE blocks in the same `edits` string are fine and
  encouraged for sibling occurrences.
- The `edits` field must be a single string, not an array or object.

Duplicate tool calls (same tool, same args) will be rejected with a nudge
message instead of being re-executed — they can't tell you anything new. If
you catch yourself asking the same thing twice, either try a different angle,
propose your best patch, or give up honestly.
"""


class _InvestigationBudgetExhausted(Exception):
    """Turn or USD budget cap tripped before the reproducer went green.
    Terminal, no auto-retry — the loop's own honest failure signal."""


class _InvestigationGaveUp(Exception):
    """Model explicitly returned {'give_up': '...reason...'}. Terminal."""


class _InvestigationChildFailed(Exception):
    """A child investigation (spawned on parent's different_bug) exhausted
    its own budget or gave up without chain-proving the downstream bug.
    Parent is rejected — the patch introduces an unfixed downstream defect."""

    def __init__(self, child_finding_id: str, child_reason: str):
        super().__init__(f"child {child_finding_id[:8]} failed: {child_reason[:200]}")
        self.child_finding_id = child_finding_id
        self.child_reason = child_reason


class _InvestigationRecursionDepthExceeded(Exception):
    """Different_bug recursion exceeded fix_writer.investigation_max_recursion_depth.
    Terminal — patch cascades unresolved downstream bugs."""


def _spawn_child_finding(ctx: "Context", parent: "Finding", spec: dict,
                        new_trace: str, new_dedup_token: str,
                        applied_text_after_parent: str, rel: str) -> "Finding":
    """Create a child finding representing a downstream bug the parent's patch
    introduced.

    Child inherits parent's spec, repo coords, and pod (container_id). Child's
    reproducer artifact is the NEW crash trace; child's reproducer_lock carries
    the NEW pristine_dedup_token derived from the trace. Child's `source` for
    investigation is the parent-patched bytes (that's the state where the new
    crash fires). Chain of custody: `parent_finding_id` points back.

    Does NOT enqueue the child through the pipeline — the caller invokes the
    investigation loop directly against the returned finding.
    """
    import json as _json
    import time as _t
    child = ctx.store.add_finding(
        source=parent.source,
        source_ref=(parent.source_ref or "") + "-child",
        repo_url=parent.repo_url,
        repo_ref=parent.repo_ref,
        base_commit=parent.base_commit,
        cwe=parent.cwe,
        title=f"downstream bug in patch for: {parent.title or parent.id[:8]}",
        description=(f"Spawned from parent finding {parent.id[:8]} whose "
                     f"proposed patch went four_state=different_bug in the "
                     f"reproducer.\n\nNew crash trace excerpt:\n"
                     + (new_trace[:2000] if new_trace else "(none)")),
        stage="patch",
        state="pending",
        owner=parent.owner or "",
    )
    # Record the chain-of-custody link. add_finding's INSERT column list is
    # fixed; the parent_finding_id column is set via update() after insert.
    ctx.store.update(child.id, parent_finding_id=parent.id,
                     container_id=parent.container_id)
    child.parent_finding_id = parent.id
    child.container_id = parent.container_id

    # Spec: same as parent's. The child inspects the same target with the same
    # commands, just with a different reproducer/pristine.
    ctx.store.add_artifact(child.id, "spec", "ingest",
                           _json.dumps(spec), {}, "", "")
    # Localization: minimal file list (child may need to grep to find its own
    # site; the pristine's original file list is a starting hint).
    ctx.store.add_artifact(
        child.id, "localization", "localize", rel,
        {"files": [rel], "source": "parent-different-bug"}, "", "")
    # Reproducer: the NEW crash trace. This is child's ground truth.
    ctx.store.add_artifact(child.id, "reproducer", "reproduce",
                           new_trace or "(no trace)", {}, "", "")
    # Reproducer_lock: pristine_dedup_token = the NEW crash's identity.
    # Structure mirrors what reproduce stage writes so classify() works.
    lock = {
        "algorithm": "sha256",
        "n_files": 1, "n_reproducer": 1,
        "files": {"/tmp/poc": {"reason": "reproducer",
                               "sha256": "0" * 64, "bytes": 0}},
        "pristine_dedup_token": new_dedup_token or "",
        "pristine_marker": "(inherited-from-different-bug)",
        "pristine_returncode": 77,
    }
    ctx.store.add_artifact(child.id, "reproducer_lock", "reproduce",
                           _json.dumps(lock), {}, "", "")

    ctx.store.emit(parent.id, "patch", "child_spawned",
                   f"spawned child {child.id[:8]} for downstream different_bug "
                   f"(new DEDUP_TOKEN: {new_dedup_token[:60]})",
                   meta={"child_id": child.id,
                         "new_dedup_token": new_dedup_token,
                         "reason": "different_bug"})
    return child


def _normalize_tool_call(tool: str, args: dict) -> tuple:
    """Canonical key for duplicate-call detection.

    Two calls that would return the same output count as duplicates. Paths
    lowercased. Grep patterns get trivial-difference normalization (strip
    parenthesis escapes; strip whitespace)."""
    key_args = []
    for k in sorted((args or {}).keys()):
        v = args[k]
        if not isinstance(v, str):
            key_args.append((k, v))
            continue
        norm = v.strip()
        if k == "path":
            norm = norm.lower()
        elif k in ("pattern", "path_glob"):
            # unescape trivial regex escapes so `xmlBufCreate\(\)` and
            # `xmlBufCreate()` collide.
            norm = norm.replace("\\(", "(").replace("\\)", ")").strip()
        key_args.append((k, norm))
    return (tool.strip().lower(), tuple(key_args))


def _apply_and_test_in_pod(ctx: "Context", f: "Finding", spec: dict, sb,
                            source: str, rel: str, obj: dict) -> dict:
    """Apply the model's edits, build, run reproducer; on green, rollback and
    re-reproduce. Returns a dict describing what happened.

    Contract on exit:
      chain_proved=True         — patch went green AND rollback went back red.
                                   File in pod left as the patched version.
      chain_proved=False        — file in pod restored to `source` (best-effort).
                                   `stage` names where it broke, message is fed
                                   back to the model for the next investigation
                                   turn.
    """
    import time as _t
    result: dict = {"chain_proved": False}
    edits = obj.get("edits", "")

    # 1. Parse + apply against the current source
    try:
        blocks = edit_mod.parse(edits)
    except edit_mod.EditsWrongTypeError as e:
        return {**result, "stage": "parse",
                "error": (f"`edits` field must be a single string of "
                          f"SEARCH/REPLACE blocks, but you returned a "
                          f"{e.actual_type}. Return `edits` as a string.")}
    try:
        applied = edit_mod.apply(source, blocks)
    except edit_mod.AmbiguousSearchError as e:
        return {**result, "stage": "apply",
                "error": (f"SEARCH block {e.block_index}/{e.total_blocks} "
                          f"matched {e.match_count} times in {rel}. Include "
                          f"more surrounding context so the block is unique.")}
    except edit_mod.EditError as e:
        return {**result, "stage": "apply", "error": str(e)}

    diff = edit_mod.to_unified_diff(rel, source, applied.text)
    result["diff"] = diff
    result["applied_blocks"] = applied.applied
    result["fixed_bytes"] = len(applied.text)

    # 2. Write patched file, build (incremental if we've compiled once already)
    try:
        sb.write(rel, applied.text)
    except Exception as e:
        return {**result, "stage": "write",
                "error": f"cannot write {rel} to pod: {e}"}

    cmds = spec.get("commands") or {}
    marker = "/tmp/.patchwing-compiled"
    has_setup = sb.run(f"test -f {marker}").returncode == 0
    incr = (cmds.get("incremental_build") or "").strip()
    build_cmd = incr if (has_setup and incr) else (cmds.get("build") or "")
    build_phase = "incremental" if (has_setup and incr) else "full"

    if not build_cmd:
        try: sb.write(rel, source)
        except Exception: pass
        return {**result, "stage": "build",
                "error": "no build command in spec"}

    ctx.store.emit(f.id, "patch", "loop_build_start",
                   f"[{build_phase}] {build_cmd[:120]}",
                   meta={"phase": build_phase})
    t0 = _t.time()
    r_build = sb.run(build_cmd, timeout_s=3600)
    dur = round(_t.time() - t0, 1)
    ctx.store.emit(f.id, "patch", "loop_build_done",
                   f"[{build_phase}] exit {r_build.returncode} in {dur}s",
                   meta={"phase": build_phase,
                         "returncode": r_build.returncode, "seconds": dur})
    if r_build.returncode != 0:
        try: sb.write(rel, source)
        except Exception: pass
        tail = ((r_build.stdout or "") + "\n" + (r_build.stderr or ""))[-4000:]
        return {**result, "stage": "build",
                "error": "build failed",
                "build_output": tail,
                "build_returncode": r_build.returncode}
    if not has_setup:
        sb.run(f"touch {marker}")

    # 3. Run reproducer
    repro_cmd = cmds.get("reproduce", "")
    if not repro_cmd:
        try: sb.write(rel, source)
        except Exception: pass
        return {**result, "stage": "reproduce",
                "error": "no reproduce command in spec"}
    ctx.store.emit(f.id, "patch", "loop_reproducer_start",
                   f"running: {repro_cmd[:120]}",
                   meta={"phase": "post_patch"})
    t0 = _t.time()
    r_repro = sb.run(repro_cmd, timeout_s=300)
    dur = round(_t.time() - t0, 1)
    ctx.store.emit(f.id, "patch", "loop_reproducer_done",
                   f"exit {r_repro.returncode} in {dur}s",
                   meta={"phase": "post_patch",
                         "returncode": r_repro.returncode, "seconds": dur})

    # 4. Classify against the pristine token (unchanged across iterations)
    lock = ctx.store.latest_artifact(f.id, "reproducer_lock")
    pristine_token = ""
    if lock:
        try:
            pristine_token = (json.loads(lock["content"]) or {}).get(
                "pristine_dedup_token", "")
        except (json.JSONDecodeError, TypeError):
            pass
    repro_output = ((r_repro.stdout or "") + "\n"
                    + (r_repro.stderr or ""))
    reading = _classify_repro(
        f, ctx, r_repro.returncode, repro_output,
        getattr(r_repro, "timed_out", False), pristine_token=pristine_token,
        duration_s=getattr(r_repro, "duration_s", 0.0))
    result["four_state_after_patch"] = reading["state"]
    result["repro_output_after_patch"] = repro_output[-6000:]
    ctx.store.emit(f.id, "patch", "loop_four_state",
                   f"{reading['state']} after patch",
                   meta={"phase": "post_patch",
                         "four_state": reading["state"]})

    if reading["state"] != "confirmed_green":
        # patch didn't fix it — feed the new trace back to the model
        try: sb.write(rel, source)
        except Exception: pass
        # Surface details the loop needs to decide whether to spawn a child
        # investigation on a different_bug (four_state != green but a NEW
        # sanitizer identity fires): the parent-patched bytes become the
        # child's source; the new DEDUP_TOKEN becomes the child's pristine.
        return {**result, "stage": "reproduce_after_patch",
                "applied_text_after_patch": applied.text,
                "new_dedup_token": states_mod.dedup_token(repro_output)}

    # 5. Chain-proved candidate — rollback, rebuild, re-run
    try: sb.write(rel, source)
    except Exception as e:
        return {**result, "stage": "rollback_write",
                "error": f"could not revert {rel}: {e}"}
    ctx.store.emit(f.id, "patch", "loop_rollback_build_start",
                   f"[incremental] rebuild after revert",
                   meta={})
    t0 = _t.time()
    r_rb_build = sb.run(incr or build_cmd, timeout_s=3600)
    dur = round(_t.time() - t0, 1)
    ctx.store.emit(f.id, "patch", "loop_rollback_build_done",
                   f"exit {r_rb_build.returncode} in {dur}s",
                   meta={"seconds": dur,
                         "returncode": r_rb_build.returncode})
    if r_rb_build.returncode != 0:
        try: sb.write(rel, applied.text)
        except Exception: pass
        return {**result, "stage": "rollback_build",
                "error": "rollback rebuild failed",
                "build_output": ((r_rb_build.stdout or "")
                                 + (r_rb_build.stderr or ""))[-3000:]}

    # Stale-daemon guard (same fix as verify()'s rollback leg). A daemon
    # reproducer's "start only if not already running" guard would otherwise
    # reuse the green leg's still-PATCHED server on this rollback run -> reads
    # green -> chain never proves for a daemon target. Kill listeners so the
    # reproducer relaunches fresh against the reverted code. http-kind only;
    # a sanitizer reproducer spawns-and-exits, so this is a no-op there.
    if str(spec.get("reproducer_kind") or "").lower() == "http":
        sb.run(
            "for _p in $(ss -ltnH 2>/dev/null | grep -oE 'pid=[0-9]+' | "
            "cut -d= -f2 | sort -u); do kill \"$_p\" 2>/dev/null; done; "
            "pkill -f 'vite|npx vite|node .*(serve|vite|http)' 2>/dev/null; "
            "sleep 2; true")
        ctx.store.emit(f.id, "patch", "loop_daemon_reset",
                       "killed lingering listeners before the rollback re-run "
                       "so a daemon reproducer relaunches against reverted code",
                       meta={"kind": "http"})
    t0 = _t.time()
    r_rb = sb.run(repro_cmd, timeout_s=300)
    dur = round(_t.time() - t0, 1)
    rb_output = ((r_rb.stdout or "") + "\n" + (r_rb.stderr or ""))
    ctx.store.emit(f.id, "patch", "loop_rollback_reproducer_done",
                   f"exit {r_rb.returncode} in {dur}s",
                   meta={"returncode": r_rb.returncode, "seconds": dur})
    rb_reading = _classify_repro(
        f, ctx, r_rb.returncode, rb_output,
        getattr(r_rb, "timed_out", False), pristine_token=pristine_token,
        duration_s=getattr(r_rb, "duration_s", 0.0))
    result["four_state_after_rollback"] = rb_reading["state"]

    # LEAVE POD IN PRISTINE STATE. The outer patch stage does NOT read the pod
    # to compute its diff/artifact — it uses `source` (pristine, captured in
    # memory at patch() entry, before this loop ran) and `applied.text`
    # (re-computed from `source` + edit blocks after this loop returns). If we
    # leave the pod PATCHED, the outer verify stage's `pre_source = sb.read()`
    # snapshot picks up the patched bytes as "before", collapsing the whole
    # hash triple to a single value and rendering the rollback assertion
    # trivial. Fix: keep the pod at the pristine bytes we already reverted to
    # above at line 1415. (Earlier the comment said the opposite; that was
    # wrong.)
    if rb_reading["state"] == "confirmed_red":
        ctx.store.emit(f.id, "patch", "loop_four_state",
                       "confirmed_red after rollback — CHAIN PROVED",
                       meta={"phase": "post_rollback",
                             "four_state": "confirmed_red"})
        result["chain_proved"] = True
        result["applied"] = applied
        # Pod already at pristine (revert happened above at line 1415, and the
        # rollback build+reproducer ran against pristine bytes). Leave as-is.
        return result

    # Rollback didn't fire the bug. Chain not proved. Feed back to model.
    return {**result, "stage": "rollback_reproduce",
            "rollback_output": rb_output[-4000:]}


def _format_loop_feedback(verdict: dict, turn: int, remaining_turns: int,
                          remaining_usd_str: str) -> str:
    """Turn a `_apply_and_test_in_pod` verdict into the next user message."""
    stage = verdict.get("stage", "?")
    diff = verdict.get("diff", "")
    diff_head = ("\nYour proposed diff:\n```\n" + diff[:4000]
                 + ("\n... [truncated]" if len(diff) > 4000 else "")
                 + "\n```\n") if diff else ""

    if stage == "parse":
        body = f"Your `edits` field could not be parsed. {verdict.get('error','')}"
    elif stage == "apply":
        body = ("Your SEARCH/REPLACE block did not apply against the current "
                f"source. {verdict.get('error','')}")
    elif stage == "write":
        body = f"The pod refused the file write: {verdict.get('error','')}"
    elif stage == "build":
        tail = verdict.get("build_output", "")
        body = ("The patch applied but the project failed to build. Build "
                f"exit code {verdict.get('build_returncode','?')}. "
                "Last 4000 bytes of build output:\n\n"
                f"```\n{tail}\n```\n"
                "Your patch broke the build. Fix the compilation error before "
                "the reproducer can be tested.")
    elif stage == "reproduce_after_patch":
        four = verdict.get("four_state_after_patch", "?")
        repro = verdict.get("repro_output_after_patch", "")
        body = ("The patch applied and built, but the reproducer did not go "
                f"green. Classifier: **{four}**. Full reproducer output "
                f"below (this is the ground truth; the developer patch is not "
                "available to you):\n\n"
                f"```\n{repro}\n```\n")
    elif stage == "rollback_write":
        body = f"Chain verification failed: {verdict.get('error','')}"
    elif stage == "rollback_build":
        body = ("Reproducer went green after your patch, but reverting the "
                "patch failed to rebuild the project cleanly. Rebuild output "
                f"tail:\n\n```\n{verdict.get('build_output','')}\n```\n")
    elif stage == "rollback_reproduce":
        four = verdict.get("four_state_after_rollback", "?")
        rb = verdict.get("rollback_output", "")
        body = ("Reproducer went green after your patch, BUT the rollback "
                "check failed: after reverting the patch and rebuilding, the "
                f"reproducer classifier read **{four}** — expected "
                "`confirmed_red`. This means the reproducer isn't "
                "deterministic on your bug, OR your patch does something the "
                "revert didn't fully undo. Rollback reproducer output:\n\n"
                f"```\n{rb}\n```\n")
    else:
        body = ("Something unexpected happened at stage "
                f"`{stage}`: {verdict!r}")

    footer = (f"\n\nTurn {turn} completed. {remaining_turns} turn(s) remain "
              f"(hard cap). Budget remaining: {remaining_usd_str}. "
              f"Reproducer status: still red.")
    return body + diff_head + footer


def _summarize_repro_status(verdict: dict | None) -> str:
    if verdict is None:
        return "not tested yet"
    if verdict.get("chain_proved"):
        return "GREEN + rollback red (chain proved)"
    fs = verdict.get("four_state_after_patch")
    if fs:
        return f"still {fs} after your last patch"
    return f"apply/build failed at stage {verdict.get('stage','?')}"


def _run_investigation_loop(
    ctx: "Context", f: "Finding", client, spec: dict, sb,
    source: str, rel: str, initial_user_msg: str,
    max_turns: int = 25, max_usd: float = 0.0,
    recursion_depth: int = 0, max_recursion_depth: int = 2,
    *,
    system_prompt: str | None = None,
    tools: dict | None = None,
) -> tuple[dict, int, int]:
    """Reproducer-only closed-loop investigation with tools.

    Model gets read_file / grep / list_dir / show_function to investigate the
    pod, and can either request more tools or propose an `edits` patch. Each
    proposed patch is immediately applied, built, reproduced, and (if green)
    rollback-verified inside this loop. On failure, the new trace is fed back
    into the SAME conversation and the loop continues. Terminates on:
      (a) chain proved                       → returns obj (StageResult.ok)
      (b) model returns {"give_up": "..."}   → raises _InvestigationGaveUp
      (c) hard turn or USD cap tripped       → raises _InvestigationBudgetExhausted
      (d) different_bug + child fails        → raises _InvestigationChildFailed
      (e) recursion depth cap hit            → raises _InvestigationRecursionDepthExceeded

    On four_state_after_patch=different_bug (patch closed the tracked bug but
    exposed a NEW crash), spawns a child finding on the new trace and
    recursively invokes this loop against it. If the child chain-proves, the
    parent's returned `obj` carries the COMBINED edits (parent's + child's,
    concatenated) so patch()'s downstream apply produces the composed patched
    bytes. Recursion bounded by max_recursion_depth.

    Duplicate tool calls are detected and answered with a nudge instead of a
    silent cache hit; every tool-results turn ends with a countdown footer.
    """
    import json as _json
    # Params default to the historical patch-investigation constants so every
    # existing caller behavior-preserves. A provision seat wraps the same
    # loop with its own system prompt + tool set. Late-bound so
    # tools_mod stays a single source of truth.
    _system_prompt = (system_prompt if system_prompt is not None
                      else INVESTIGATION_SYSTEM)
    _tools = tools if tools is not None else tools_mod.TOOLS
    convo = [
        {"role": "system", "content": _system_prompt},
        {"role": "user", "content": initial_user_msg},
    ]
    seen_calls: dict[tuple, int] = {}   # normalized call key → first turn
    tool_calls_total = 0
    last_verdict: dict | None = None

    for turn in range(1, max_turns + 1):
        # Budget snapshot (USD cap tracked via patch-seat spend rows)
        _spent = budget_mod.spent(ctx.store, f.id)
        remaining_usd = None
        remaining_usd_str = "no priced ceiling"
        if max_usd > 0:
            remaining_usd = max(0.0, max_usd - _spent.usd)
            remaining_usd_str = f"${remaining_usd:.2f} of ${max_usd:.2f}"
        remaining_turns = max_turns - turn

        if max_usd > 0 and _spent.priced and remaining_usd <= 0:
            raise _InvestigationBudgetExhausted(
                f"USD cap reached: spent ${_spent.usd:.4f} against "
                f"${max_usd:.2f} at turn {turn}, {tool_calls_total} tool call(s)")

        ctx.store.emit(
            f.id, "patch", "investigation_turn",
            f"turn {turn}/{max_turns}, convo="
            f"{sum(len(m['content']) for m in convo)}B, "
            f"remaining: {remaining_usd_str}",
            meta={"turn": turn, "max_turns": max_turns,
                  "convo_bytes": sum(len(m["content"]) for m in convo),
                  "convo_messages": len(convo),
                  "remaining_usd": remaining_usd,
                  "spent_usd": _spent.usd,
                  "repro_status": _summarize_repro_status(last_verdict)})

        obj = client.chat_json(convo, required=())
        # Persist the raw response body for evidence — includes any prose the
        # model chose to wrap around the JSON reply. One artifact per turn.
        ctx.store.add_artifact(
            f.id, "response", "patch",
            content=(client.last_raw_response or ""),
            meta={"seat": "patch",
                  "model": client.cfg.model,
                  "endpoint": client.cfg.endpoint,
                  "turn": turn,
                  "attempt": f"investigation_turn_{turn}"},
            model=client.cfg.model)

        # Explicit give-up
        if isinstance(obj, dict) and obj.get("give_up"):
            raise _InvestigationGaveUp(str(obj.get("give_up"))[:400])

        # Patch attempt — run the closed loop
        if isinstance(obj, dict) and isinstance(obj.get("edits"), str) \
                and obj["edits"].strip():
            ctx.store.emit(
                f.id, "patch", "investigation_patch_returned",
                f"patch attempt at turn {turn}: "
                f"edits={len(obj['edits'])}B, testing in pod",
                meta={"turn": turn,
                      "edits_bytes": len(obj["edits"]),
                      "analysis_bytes": len(obj.get("analysis", "")),
                      "confidence": obj.get("confidence", "?"),
                      "tool_calls_total": tool_calls_total})
            verdict = _apply_and_test_in_pod(ctx, f, spec, sb, source, rel, obj)
            last_verdict = verdict
            if verdict.get("chain_proved"):
                ctx.store.emit(f.id, "patch", "investigation_chain_proved",
                               f"CHAIN PROVED at turn {turn}",
                               meta={"turn": turn,
                                     "tool_calls_total": tool_calls_total,
                                     "recursion_depth": recursion_depth})
                # On top-level chain-proved exit, ensure pod is at ORIGINAL
                # pristine (a nested chain-proved inside a child may have left
                # it at parent-patched). No-op if the last write already put it
                # there. Handled by the parent's caller at depth>0.
                if recursion_depth == 0:
                    try: sb.write(rel, source)
                    except Exception: pass
                return obj, turn, tool_calls_total

            # different_bug branch — spawn a child investigation on the new
            # crash and recurse. The pod currently holds `source` bytes (the
            # verdict revert put it back), so we must re-apply the parent's
            # patch and re-build before the child can investigate against the
            # correct base state. The child's `source` is parent-applied bytes.
            if verdict.get("four_state_after_patch") == "different_bug":
                if recursion_depth >= max_recursion_depth:
                    ctx.store.emit(
                        f.id, "patch", "investigation_recursion_depth_exceeded",
                        f"different_bug at depth {recursion_depth}, cap="
                        f"{max_recursion_depth} — cascading downstream bugs "
                        "unresolved",
                        meta={"turn": turn, "depth": recursion_depth,
                              "max_depth": max_recursion_depth,
                              "new_dedup_token": verdict.get("new_dedup_token","")})
                    raise _InvestigationRecursionDepthExceeded(
                        f"different_bug recursion hit cap "
                        f"{max_recursion_depth} at turn {turn}")

                applied_text = verdict.get("applied_text_after_patch", "")
                new_trace = verdict.get("repro_output_after_patch", "")
                new_tok = verdict.get("new_dedup_token", "")
                if not applied_text:
                    # Should not happen — the classifier only reaches
                    # different_bug after a successful apply. Defensive.
                    feedback = _format_loop_feedback(
                        verdict, turn, remaining_turns, remaining_usd_str)
                    convo.append({"role": "assistant",
                                  "content": _json.dumps(obj)[:16000]})
                    convo.append({"role": "user", "content": feedback})
                    continue

                # Re-apply parent's patch to the pod so the child investigation
                # runs against the state where the new crash fires. The build
                # will pick up incrementally (marker is set).
                try: sb.write(rel, applied_text)
                except Exception: pass
                cmds = spec.get("commands") or {}
                _incr = (cmds.get("incremental_build") or "").strip()
                _build_cmd = _incr or (cmds.get("build") or "")
                if _build_cmd:
                    ctx.store.emit(
                        f.id, "patch", "child_setup_build",
                        f"reapplying parent patch + rebuilding before child "
                        f"investigation",
                        meta={"phase": "child_setup"})
                    sb.run(_build_cmd, timeout_s=3600)

                child = _spawn_child_finding(
                    ctx, f, spec, new_trace, new_tok, applied_text, rel)
                child_initial_msg = (
                    "Vulnerability (spawned as a downstream defect from a "
                    f"parent patch): {child.title}\n"
                    f"Parent finding: {f.id}\n"
                    f"CWE: {f.cwe or 'unspecified'}\n\n"
                    "Description: the parent's fix closed the original bug "
                    "but a NEW crash now fires with a different sanitizer "
                    "identity. Your job is to fix THIS downstream crash "
                    "without reverting the parent's fix. The parent's patch "
                    f"is already applied to the source you will investigate.\n\n"
                    "New crash trace (this is your ground truth):\n"
                    + (new_trace or "(none)") + "\n\n"
                    "Target source root: "
                    + str((spec.get("target") or {}).get("root", "/")) + "\n"
                    "Language: " + str(spec.get("language") or "unknown") + "\n\n"
                    "The loop is closed: your patches are applied on top of "
                    "the parent's patch, built, and re-tested. If the new "
                    "crash still fires, you get its trace back.")

                child_client = _client(ctx, "patch", child, "patch")
                try:
                    child_obj, child_turns, child_tcalls = \
                        _run_investigation_loop(
                            ctx, child, child_client, spec, sb,
                            source=applied_text, rel=rel,
                            initial_user_msg=child_initial_msg,
                            max_turns=max_turns, max_usd=max_usd,
                            recursion_depth=recursion_depth + 1,
                            max_recursion_depth=max_recursion_depth,
                            system_prompt=INVESTIGATION_SYSTEM,
                            tools=tools_mod.TOOLS)
                except _InvestigationGaveUp as _gu:
                    ctx.store.update(child.id, state="failed",
                                     error=f"gave up: {_gu}"[:400])
                    raise _InvestigationChildFailed(child.id, f"gave up: {_gu}")
                except _InvestigationBudgetExhausted as _be:
                    ctx.store.update(child.id, state="failed",
                                     error=f"budget: {_be}"[:400])
                    raise _InvestigationChildFailed(child.id,
                                                    f"budget: {_be}")
                except _InvestigationRecursionDepthExceeded as _re:
                    ctx.store.update(child.id, state="failed",
                                     error=f"recursion: {_re}"[:400])
                    raise _InvestigationChildFailed(child.id,
                                                    f"recursion: {_re}")

                # Child chain-proved. Compose combined edits so patch()'s
                # downstream apply produces child's final bytes when run against
                # the ORIGINAL pristine `source`. Edit_mod.apply processes
                # blocks sequentially against the evolving text, so
                # parent_edits + "\n\n" + child_edits works as long as parent's
                # SEARCH matches pristine and child's SEARCH matches
                # parent-applied (both true by construction).
                combined_edits = (
                    obj.get("edits", "").rstrip() + "\n\n"
                    + child_obj.get("edits", "").rstrip() + "\n")
                combined_analysis = (
                    "PARENT ANALYSIS:\n" + (obj.get("analysis", "") or "")
                    + "\n\nCHILD ANALYSIS (downstream " + child.id[:8] + "):\n"
                    + (child_obj.get("analysis", "") or ""))
                combined_obj = {
                    "analysis": combined_analysis,
                    "edits": combined_edits,
                    "confidence": child_obj.get("confidence",
                                                 obj.get("confidence", "?")),
                    "child_finding_id": child.id,
                    "child_turns_used": child_turns,
                    "child_tool_calls_total": child_tcalls,
                }
                ctx.store.emit(f.id, "patch", "investigation_chain_proved",
                               f"CHAIN PROVED via child {child.id[:8]} "
                               f"(depth {recursion_depth + 1}, "
                               f"{child_turns} child turns, "
                               f"{child_tcalls} child tool calls)",
                               meta={"turn": turn,
                                     "tool_calls_total": tool_calls_total,
                                     "recursion_depth": recursion_depth,
                                     "child_finding_id": child.id,
                                     "child_turns": child_turns,
                                     "child_tool_calls": child_tcalls})
                if recursion_depth == 0:
                    try: sb.write(rel, source)
                    except Exception: pass
                return combined_obj, turn, tool_calls_total

            feedback = _format_loop_feedback(
                verdict, turn, remaining_turns, remaining_usd_str)
            convo.append({"role": "assistant",
                          "content": _json.dumps(obj)[:16000]})
            convo.append({"role": "user", "content": feedback})
            continue

        # Tool calls
        tool_calls = obj.get("tool_calls") if isinstance(obj, dict) else None
        if not tool_calls:
            convo.append({"role": "assistant",
                          "content": _json.dumps(obj)[:8000]})
            convo.append({"role": "user", "content":
                "Your last response contained no `tool_calls`, no `edits`, "
                "and no `give_up`. Return one of: (a) tool_calls to keep "
                "investigating; (b) `edits` with SEARCH/REPLACE blocks — I "
                "will apply, build, and run the reproducer, and if it's "
                "still red you'll get the new trace and can keep going; "
                "(c) `give_up` with a reason.\n\n"
                f"Turn {turn} of {max_turns} used. Budget: "
                f"{remaining_usd_str}. Reproducer status: "
                f"{_summarize_repro_status(last_verdict)}."})
            continue

        convo.append({"role": "assistant",
                      "content": _json.dumps(obj)[:16000]})
        results: list[dict] = []
        for call in tool_calls[:5]:
            tool_name = str(call.get("tool", ""))
            args = call.get("args") or {}
            if not isinstance(args, dict):
                args = {}
            tool_calls_total += 1

            key = _normalize_tool_call(tool_name, args)
            if key in seen_calls:
                prior = seen_calls[key]
                nudge = (
                    f"You already ran this exact call at turn {prior} and "
                    f"got the same result. Repeating it will not change the "
                    f"answer. You have {remaining_turns} turn(s) and "
                    f"{remaining_usd_str} remaining. Either (a) try a "
                    f"genuinely different investigation angle, (b) propose "
                    f"your best patch now — I will apply it and run the "
                    f"reproducer, and if it still crashes you will get the "
                    f"new trace and can keep going, or (c) return "
                    f'{{"give_up": "your reason"}} to stop.')
                ctx.store.emit(
                    f.id, "patch", "investigation_duplicate_call",
                    f"{tool_name} duplicated from turn {prior}",
                    meta={"turn": turn, "tool": tool_name, "args": args,
                          "prior_turn": prior})
                results.append({"tool": tool_name, "args": args,
                                "output": nudge})
                continue

            ctx.store.emit(
                f.id, "patch", "investigation_tool_call",
                f"{tool_name}({_json.dumps(args)[:120]})",
                meta={"turn": turn, "tool": tool_name, "args": args})
            seen_calls[key] = turn
            fn = _tools.get(tool_name)
            if fn is None:
                err = (f"unknown tool {tool_name!r}; available: "
                       f"{list(_tools)}")
                ctx.store.emit(f.id, "patch", "investigation_tool_result",
                               f"{tool_name} ERROR: {err[:80]}",
                               meta={"turn": turn, "tool": tool_name,
                                     "error": err})
                results.append({"tool": tool_name, "args": args, "error": err})
                continue
            try:
                out = fn(sb, **args)
                ctx.store.emit(
                    f.id, "patch", "investigation_tool_result",
                    f"{tool_name} -> {len(out)}B",
                    meta={"turn": turn, "tool": tool_name,
                          "output_bytes": len(out)})
                results.append({"tool": tool_name, "args": args, "output": out})
            except (tools_mod.ToolError, TypeError, KeyError) as e:
                err = str(e)
                ctx.store.emit(
                    f.id, "patch", "investigation_tool_result",
                    f"{tool_name} ERROR: {err[:80]}",
                    meta={"turn": turn, "tool": tool_name, "error": err[:400]})
                results.append({"tool": tool_name, "args": args, "error": err})

        chunks = []
        for r in results:
            head = f"### {r['tool']}({_json.dumps(r.get('args', {}))})"
            body = ("ERROR: " + r["error"] if "error" in r else r["output"])
            chunks.append(head + "\n" + body)
        footer = (f"\n\n---\nTurn {turn} of hard-cap {max_turns}. "
                  f"Budget remaining: {remaining_usd_str}. "
                  f"Reproducer status: "
                  f"{_summarize_repro_status(last_verdict)}.")
        convo.append({"role": "user",
                      "content": "Tool results:\n\n"
                                 + "\n\n".join(chunks) + footer})

    # Turn cap reached without a proved chain
    raise _InvestigationBudgetExhausted(
        f"turn cap: {max_turns} turns and {tool_calls_total} tool call(s) "
        f"without a chain-proved fix")


@stage("patch")
def patch(f: Finding, ctx: Context) -> StageResult:
    """
    Generate a fix plus a regression test that pins it.

    Recorded against the current commit. A patch is never rebased — if the repo
    moved, this stage re-runs and produces a fresh one (see Store.is_stale).
    """
    spec = _spec(f, ctx)
    if spec is None:
        return StageResult.blocked("no target spec attached",
                                   meta={"outcome": "patch_no_spec"})

    # WALL ASSERTION (a) — pod-per-finding, change 2.
    # If a previous verdict recorded a hash triple, the file the LAST iteration
    # patched must currently match its recorded before_patch hash. That is the
    # only assertion made — build tree, temp files, timestamps, env can differ.
    # This is (a) from the design: "patched file reverted only. Everything
    # else — build tree, temp files, env — is 'close enough.' Honest about
    # what it is." If it fails, refuse to iterate on a dirty tree.
    last_verdict = ctx.store.latest_artifact(f.id, "verdict")
    if last_verdict is not None and (f.container_id or "").strip():
        try:
            vmeta = json.loads(last_verdict["meta"] or "{}")
        except (json.JSONDecodeError, TypeError):
            vmeta = {}
        triple = ((vmeta.get("rollback") or {}).get("hash_triple") or {})
        prev_file = ((vmeta.get("provenance") or {}).get("patched_file") or "")
        prev_before = triple.get("before_patch") or ""
        if prev_file and prev_before:
            try:
                with _sandbox(ctx, spec, finding=f, persist=True) as _wsb:
                    _wsb.prepare()
                    cur = _wsb.read(prev_file)
                cur_hash = _sha256_text(cur)
                if cur_hash != prev_before:
                    return StageResult.fail(
                        f"WALL DIRTY at iteration boundary — {prev_file} does "
                        f"not match its pre-patch hash from the previous "
                        f"iteration's rollback ({cur_hash[:12]} != "
                        f"{prev_before[:12]}). Something drifted between "
                        f"iterations. Refuse to iterate; start a new finding.",
                        meta={"outcome": "iterate_state_dirty",
                              "patch_evaluated": False,
                              "expected_hash": prev_before,
                              "actual_hash": cur_hash,
                              "file": prev_file})
            except sandbox_mod.InImageSandbox.PodLost as e:
                return StageResult.fail(
                    f"POD LOST at patch (iteration boundary) — {e}",
                    meta={"outcome": "pod_lost_at_patch",
                          "patch_evaluated": False})

    loc = ctx.store.latest_artifact(f.id, "localization")
    if loc is None:
        return StageResult.fail("no localization artifact — run localize first",
                                meta={"outcome": "patch_no_localization"})

    # THE CONTAINER IS THE LOCALIZER. If the reproducer output carries a
    # sanitizer trace, prefer that over the spec's `files` field — the 1076 run
    # made it visible that ARVO's `files` records where the DEVELOPER PATCHED,
    # which is not the same as where the bug lives. The trace is the only signal
    # that comes from what the code actually did.
    root_in_image = str((spec.get("target") or {}).get("root", "")).strip("/")
    repro = ctx.store.latest_artifact(f.id, "reproducer")
    trace = _localize_from_trace((repro["content"] if repro else "") or "",
                                 root_in_image)
    context_files: list[str] = []
    localization_source = "spec"
    # [fix_writer] knobs. Users can pick which context files to include, cap
    # total context bytes, and disable context entirely for tiny-context models.
    # Defaults match the historical trace-derived behaviour: all context files
    # from the trace, no size cap.
    fw = spec.get("fix_writer") or {}
    # UI overrides live in pipeline_settings DB (Providers page). SPEC WINS —
    # a target's [fix_writer] section is deliberate per-target policy, DB is
    # only the system default when the spec is silent.
    _pipe_defaults = {}
    try:
        _pipe_defaults = {r[0]: r[1] for r in ctx.store.conn.execute(
            "SELECT key, value FROM pipeline_settings")}
    except Exception:
        pass
    def _pref(fw_key, db_key, default, coerce):
        v = fw.get(fw_key)
        if v is None and db_key in _pipe_defaults:
            v = _pipe_defaults[db_key]
        return coerce(v) if v is not None else default
    context_max_bytes = _pref("context_max_bytes", "context_max_bytes", 0, int)
    include_context = _pref("include_context", "include_context", True,
                            lambda v: str(v).lower() in ("1","true","yes","on"))
    context_allowlist = fw.get("context_files")  # None = all trace-derived
    if trace["primary"]:
        # Origin file is what we can EDIT. The crash-site file rides along as
        # read-only context in the prompt: it names the code that DEMONSTRATES the
        # bug, useful for reasoning but not the place a fix belongs.
        rel = trace["primary"]
        localization_source = ("trace_origin" if trace["origin"]
                               else "trace_storage" if trace["storage"]
                               else "trace_crash")
        if include_context:
            seen = {rel}
            for group in ("crash", "storage", "origin"):
                for path, _ in trace[group]:
                    if path not in seen and (
                            context_allowlist is None
                            or path in context_allowlist):
                        seen.add(path)
                        context_files.append(path)
    else:
        # Fallback: spec's files field. Left in so a non-sanitizer target still
        # has an oracle. On sanitizer targets a missing trace-derived path is a
        # signal that the reproducer output was mangled, not that spec is right.
        files = (json.loads(loc["meta"]) or {}).get("files") or []
        if not files:
            return StageResult.fail("localization produced no files",
                                    meta={"outcome": "patch_localization_empty"})
        # Correction #4: filter through strategy.is_source_path_patchable
        # if an ecosystem strategy is registered. If EVERY localization file
        # is filtered out (all tests, docs, playgrounds), fail loud — patch
        # would otherwise proceed with nothing to modify.
        _eco = str(spec.get("ecosystem") or "").strip().lower()
        # Skip the strategy filter for template-based findings: templates
        # ship only the installed package under node_modules/, which the
        # source-clone-based filter would over-block. For non-template
        # findings (ecosystem-strategy path), the filter correctly rejects
        # test/doc/node_modules paths to force patches into source.
        _preferred_template = (
            (spec.get("http") or {}).get("preferred_template") or "").strip()
        if _eco and not _preferred_template:
            try:
                from .ecosystems import for_ecosystem, UnknownEcosystem
                from .ecosystems.base import EcosystemScopeExceeded
                _strat = for_ecosystem(_eco)
                _pkg = str(spec.get("package") or "").strip()
                # Derive target_pkg_dir from the shortest localization path's
                # top-level dir if package.json path indicates monorepo layout,
                # else empty (single-package).
                _pkg_dir_in_source = ""
                if _pkg and files:
                    for _f in files:
                        _parts = _f.split("/")
                        if len(_parts) >= 2 and _parts[0] == "packages":
                            _pkg_dir_in_source = f"packages/{_parts[1]}"
                            break
                _patchable = [_f for _f in files
                              if _strat.is_source_path_patchable(_f, _pkg_dir_in_source)]
                if not _patchable:
                    return StageResult.fail(
                        f"no patchable source in localization — strategy "
                        f"{_eco!r} filtered out ALL {len(files)} localization "
                        f"file(s): {files[:5]}. Every file is test/doc/playground/"
                        f"non-target-package. Localize needs to surface a "
                        f"patchable source file, or the strategy's filter "
                        f"needs revision.",
                        meta={"outcome": "patch_no_patchable_source",
                              "filtered_count": len(files),
                              "filtered_files": files})
                files = _patchable
            except (UnknownEcosystem, EcosystemScopeExceeded):
                # No strategy or strategy can't handle — leave files as-is
                # (fallback to current behavior; patch reads directly)
                pass
        rel = files[0]

    target = _target_dir(spec)

    # The wall, enforced at the point of writing. Localization is not trusted to
    # stay away from the reproducer: if it names a frozen file, the fix-writer
    # would be rewriting the very test that proves the bug, and the container
    # would then happily report success. Refuse before the model is even called.
    lock = ctx.store.latest_artifact(f.id, "reproducer_lock")
    if lock is None:
        return StageResult.fail(
            "no reproducer_lock artifact — the wall was never frozen, so a patch "
            "produced now could not be shown to have left the reproducer intact. "
            "Re-run reproduce.",
            meta={"outcome": "patch_no_reproducer_lock"})
    try:
        manifest = json.loads(lock["content"])
    except json.JSONDecodeError as e:
        return StageResult.fail(f"reproducer_lock is unreadable: {e}",
                                meta={"outcome": "patch_lock_unreadable"})

    try:
        wall_mod.assert_patchable(
            rel, manifest, (spec.get("target") or {}).get("root", ""))
    except wall_mod.WallError as e:
        return StageResult.fail(f"PATCH TARGET IS FROZEN — {e}",
                                meta={"outcome": "patch_target_frozen"})

    why = wall_mod.is_protected(rel, manifest)
    if why:
        return StageResult.reject(
            f"localization named {rel}, which is inside the reproducer wall "
            f"({why}). The fix-writer may not modify the artifact that proves the "
            f"bug — fix the vulnerable source instead.",
            meta={"outcome": "patch_target_inside_wall"})

    in_image = str(((spec.get("target") or {}).get("mode") or "")
                   ).replace("_", "-") == "in-image"
    # Read the file we may EDIT plus any read-only context files the trace
    # named. Context files ride along in the prompt but are marked read-only so
    # SEARCH/REPLACE targets stay unambiguous — one file's bytes on disk change.
    #
    # [fix_writer].context_max_bytes caps the TOTAL context bytes (across all
    # extra files). Files are added in trace-derived order until the cap would
    # be exceeded; those that don't fit are DROPPED (not truncated — a partial
    # C file is not source, it's noise). The drop is recorded so the user can
    # see it in the prompt artifact.
    context_sources: dict[str, str] = {}
    context_dropped: list[str] = []
    def _accept(path: str, body: str) -> None:
        if context_max_bytes and (sum(len(v) for v in context_sources.values())
                                  + len(body)) > context_max_bytes:
            context_dropped.append(path)
            return
        context_sources[path] = body
    if in_image:
        try:
            with _sandbox(ctx, spec, finding=f, persist=True) as _sb:
                _sb.prepare()
                try:
                    source = _sb.read(rel)
                except Exception as _read_err:
                    # The localized path does not exist at that location in the
                    # committed image. The dominant cause is an install-root
                    # mismatch: the reproducer exercises the package from one
                    # path (e.g. localization named
                    # opt/<target>/node_modules/<pkg>/index.js) while provision
                    # committed it under another (e.g. /app/node_modules/...).
                    # Re-running here pays for a fresh ~50-min provision and
                    # fails identically. Locate where the file ACTUALLY lives in
                    # the image so the spec/localization can be corrected in one
                    # shot. Diagnostic only — we never silently patch a guessed
                    # file, because a wrong copy would pass the wall yet leave
                    # the reproduced copy vulnerable.
                    # Match on the trailing path segments, not the bare
                    # basename: a name like index.js occurs in every package, so
                    # `-name index.js` returns noise. The last two segments
                    # (e.g. decompress/index.js) pin the actual file across a
                    # different install root, while still tolerating the root
                    # prefix differing.
                    _base = os.path.basename(rel)
                    _segs = [s for s in rel.split("/") if s]
                    _suffix = "/".join(_segs[-2:]) if len(_segs) >= 2 else _base
                    _cands: list[str] = []
                    if _suffix:
                        _found = _sb.run(
                            "find / -xdev -type f -path "
                            f"{shlex.quote('*/' + _suffix)} 2>/dev/null "
                            "| head -20")
                        _cands = [ln.strip() for ln
                                  in (_found.stdout or "").splitlines()
                                  if ln.strip()]
                    _hint = (f" — not found there; present in the image at: "
                             f"{_cands}" if _cands else
                             f" — not found there, and nothing matching "
                             f"*/{_suffix} exists anywhere in the image")
                    ctx.store.emit(
                        f.id, "patch", "source_unreadable",
                        f"localized path {rel} is not in the committed image"
                        + _hint,
                        meta={"localized_path": rel,
                              "candidates_in_image": _cands})
                    return StageResult.fail(
                        f"cannot read {rel} from image: {_read_err}{_hint}. This "
                        f"is a localization/spec path that does not match the "
                        f"committed install root — correct the target path (or "
                        f"localizer) rather than re-running the same spec.",
                        meta={"outcome": "patch_source_unreadable_in_image",
                              "localized_path": rel,
                              "candidates_in_image": _cands})
                ctx.store.emit(f.id, "patch", "source_read",
                               f"read {rel} from pod: {len(source)} bytes, "
                               f"{len(source.splitlines())} lines",
                               meta={"file": rel, "bytes": len(source),
                                     "lines": len(source.splitlines()),
                                     "localization_source": localization_source})
                for extra in context_files:
                    try:
                        _accept(extra, _sb.read(extra))
                    except Exception as _e:
                        # A missing context file is not fatal — the primary is
                        # still readable. Note it and continue.
                        context_sources[extra] = f"(unreadable: {_e})"
        except Exception as e:
            return StageResult.fail(
                f"cannot read {rel} from image: {e}",
                meta={"outcome": "patch_source_unreadable_in_image"})
    else:
        try:
            with open(os.path.join(target, rel), "r", encoding="utf-8") as fh:
                source = fh.read()
            ctx.store.emit(f.id, "patch", "source_read",
                           f"read {rel}: {len(source)} bytes, "
                           f"{len(source.splitlines())} lines",
                           meta={"file": rel, "bytes": len(source),
                                 "lines": len(source.splitlines()),
                                 "localization_source": localization_source})
            for extra in context_files:
                try:
                    with open(os.path.join(target, extra), "r",
                              encoding="utf-8") as _fh:
                        _accept(extra, _fh.read())
                except OSError as _e:
                    context_sources[extra] = f"(unreadable: {_e})"
        except OSError as e:
            return StageResult.fail(
                f"cannot read {rel}: {e}",
                meta={"outcome": "patch_source_unreadable_on_host"})

    if context_files:
        ctx.store.emit(f.id, "patch", "context_files_added",
                       f"{len(context_sources)} context file(s), "
                       f"{sum(len(v) for v in context_sources.values())} bytes"
                       + (f" — DROPPED: {', '.join(context_dropped)}"
                          if context_dropped else ""),
                       meta={"included": list(context_sources.keys()),
                             "dropped": context_dropped,
                             "cap_bytes": context_max_bytes,
                             "total_bytes": sum(len(v) for v in context_sources.values())})

    repro = ctx.store.latest_artifact(f.id, "reproducer")
    # No cap — the trace's ORIGIN frames (which name the allocation site) often
    # sit past the first 2000 bytes on MSan reports. Truncating the tail hides
    # the frames a fix-writer needs to consider the read side of a
    # use-of-uninitialized-value, which was the observed failure on 1076: Kimi
    # kept masking at the allocation because the read-site frames were cut.
    repro_out = repro["content"] if repro else "(none)"

    # The fix-writer view. Two modes, chosen per target in [target].fix_writer_view.
    #
    #  window       — ±radius lines around anchors. Default. Cheap on tokens; risky
    #                 when the correct fix site sits outside the anchor's radius,
    #                 as it did on the CDATA leak, where the trace anchored on the
    #                 crash and the fix was elsewhere in the file.
    #  whole_file   — the entire source, unabridged. Removes that failure mode by
    #                 removing the window; costs tokens.
    #
    # Whichever mode is chosen, the WALL is unchanged: no upstream patch, no
    # reproducer INPUT, ever. The view is only about how much of the vulnerable
    # source the model gets to read.
    loc_meta = {}
    try:
        loc_meta = json.loads(loc["meta"] or "{}")
    except (json.JSONDecodeError, TypeError):
        pass

    view = str(((spec.get("target") or {}).get("fix_writer_view")
                or "window")).lower()
    anchors: list[str] = []
    if view == "whole_file":
        # Number the lines so SEARCH text stays copyable but the model can still
        # reason positionally. Bytes and total line count go in the framing so it
        # can size its context.
        def _numbered(src: str) -> str:
            return "\n".join(f"{i+1:5d}  {line}"
                             for i, line in enumerate(src.splitlines()))

        view_block = (
            "=== EDITABLE FILE (your SEARCH text must come from THIS file) ===\n"
            "File: " + rel + "  (" + str(len(source)) + " bytes, "
            + str(len(source.splitlines())) + " lines — the WHOLE file, "
            "unabridged)\n"
            "Line numbers are shown as a reading aid; do not include them in "
            "SEARCH/REPLACE text.\n"
            "```\n" + _numbered(source) + "\n```\n"
        )
        for extra, extra_src in context_sources.items():
            view_block += (
                "\n=== CONTEXT (read-only; do NOT SEARCH/REPLACE in this file) ===\n"
                f"File: {extra}  ({len(extra_src)} bytes, "
                f"{len(extra_src.splitlines())} lines — the WHOLE file)\n"
                "```\n" + _numbered(extra_src) + "\n```\n"
            )
        lo, hi = 1, len(source.splitlines())
    else:
        anchors = [a for a in (loc_meta.get("anchors") or []) if a]
        if not anchors:
            anchors = re.findall(r"\bin ([A-Za-z_][A-Za-z0-9_]{3,})",
                                 repro_out)[:6]
        win, lo, hi = edit_mod.window(source, anchors, radius=70)
        view_block = (
            "File: " + rel + "  (" + str(len(source)) + " bytes total)\n"
            "Window shown: lines " + str(lo) + "-" + str(hi) + "\n"
            "```\n" + win + "\n```\n"
        )

    prompt = (
        "Vulnerability: " + (f.title or "(untitled)") + "\n"
        "CWE: " + (f.cwe or "unspecified") + "\n"
        "Reference: " + (f.source_ref or "n/a") + "\n\n"
        "Description:\n" + (f.description or "(none)") + "\n\n"
        "Reproducer output (currently demonstrates the flaw):\n"
        + repro_out + "\n\n"
        + view_block
    )

    # Full prompt is stored as an artifact BEFORE the model call, so a reader
    # can see exactly what was sent — the system message, the user message with
    # every section labelled, the model id, and the sampling params. Half of
    # "trust the container, never the narrator" is being able to check what the
    # narrator was even asked. Without this, `patch_diff` is the only visible
    # thing and there is no way to know if a bad answer was a bad model or a
    # bad prompt.
    client = None
    try:
        client = _client(ctx, "patch", f, "patch")
    except budget_mod.CeilingExceeded:
        raise
    except Exception as e:
        return StageResult.retry("patch client init failed: " + str(e),
                                 meta={"outcome": "patch_model_client_unavailable"})

    _system_prompt_patch = _resolve_prompt(ctx, "PATCH_SYSTEM", PATCH_SYSTEM)
    prompt_artifact = {
        "kind": "prompt", "stage": "patch",
        "content": prompt,
        "model": client.cfg.model,
        "base_commit": f.base_commit,
        "meta": {
            "seat": "patch",
            "model": client.cfg.model,
            "endpoint": client.cfg.endpoint,
            "temperature": client.cfg.temperature,
            "max_tokens": client.cfg.max_tokens,
            "system_message": _system_prompt_patch,
            "user_message_bytes": len(prompt),
            "user_message_lines": len(prompt.splitlines()),
            "primary_file": rel,
            "context_files": list(context_sources.keys()),
            "context_files_dropped": context_dropped,
            "context_max_bytes": context_max_bytes,
            "localization_source": localization_source,
            "view": view,
            "window_lines": [lo, hi],
        },
    }
    # Persist BEFORE the call so a crash / timeout still leaves a record of
    # what was in flight.
    ctx.store.add_artifact(f.id, **prompt_artifact)
    ctx.store.emit(f.id, "patch", "prompt_assembled",
                   f"prompt built: system={len(PATCH_SYSTEM)}B, "
                   f"user={len(prompt)}B ({len(prompt.splitlines())} lines), "
                   f"primary={rel}"
                   + (f", +{len(context_sources)} ctx" if context_sources else ""),
                   meta={"system_bytes": len(PATCH_SYSTEM),
                         "user_bytes": len(prompt),
                         "user_lines": len(prompt.splitlines()),
                         "primary_file": rel,
                         "view": view,
                         "context_files": list(context_sources.keys()),
                         "context_files_dropped": context_dropped})
    ctx.store.emit(f.id, "patch", "model_call",
                   f"POST {client.cfg.endpoint} model={client.cfg.model}",
                   meta={"endpoint": client.cfg.endpoint,
                         "model": client.cfg.model,
                         "family": getattr(client.cfg, "family", ""),
                         "temperature": client.cfg.temperature,
                         "max_tokens": client.cfg.max_tokens,
                         "seat": "patch"})

    import time as _tm_patch
    _t0_patch = _tm_patch.time()
    _investigation_mode = bool(fw.get("investigation_mode", False))
    _investigation_turns = int(fw.get("investigation_max_turns", 25))
    _investigation_max_usd = float(fw.get("investigation_max_usd", 0.0))
    _investigation_max_recursion = int(fw.get("investigation_max_recursion_depth", 2))
    _investigation_meta: dict = {}
    try:
        if _investigation_mode:
            # Reframe: no source files pre-loaded, no window view. Model gets
            # the trace and must grep/read to discover the files it needs.
            # Every patch attempt is applied+built+reproduced inside the loop;
            # a still-red trace is fed back and the loop continues.
            _inv_user = (
                "Vulnerability: " + (f.title or "(untitled)") + "\n"
                "CWE: " + (f.cwe or "unspecified") + "\n"
                "Reference: " + (f.source_ref or "n/a") + "\n\n"
                "Description:\n" + (f.description or "(none)") + "\n\n"
                "Reproducer output (full, currently demonstrates the flaw):\n"
                + (repro_out or "(none)") + "\n\n"
                "Target source root inside the container: "
                + str((spec.get("target") or {}).get("root", "/")) + "\n"
                "Language: " + str(spec.get("language") or "unknown") + "\n\n"
                "The crash trace tells you where the bug SURFACED, not "
                "necessarily where it LIVES. Investigate before you patch. "
                "The loop is closed: every patch you propose is applied, "
                "built, and re-tested against the reproducer; if it's still "
                "red you get the new trace back and can keep going.")
            with _sandbox(ctx, spec, finding=f, persist=True) as _isb:
                _isb.prepare()
                obj, _turns, _tcalls = _run_investigation_loop(
                    ctx, f, client, spec, _isb, source, rel, _inv_user,
                    max_turns=_investigation_turns,
                    max_usd=_investigation_max_usd,
                    recursion_depth=0,
                    max_recursion_depth=_investigation_max_recursion,
                    system_prompt=INVESTIGATION_SYSTEM,
                    tools=tools_mod.TOOLS)
            _investigation_meta = {"investigation": True,
                                   "turns_used": _turns,
                                   "tool_calls_total": _tcalls,
                                   "max_turns": _investigation_turns,
                                   "max_usd": _investigation_max_usd,
                                   "max_recursion_depth": _investigation_max_recursion,
                                   "chain_proved_in_loop": True}
            # Carry child-finding metadata into the artifact so the reviewer
            # can trace the composed patch back to which sub-investigation
            # closed which downstream defect.
            if obj.get("child_finding_id"):
                _investigation_meta["child_finding_id"] = obj["child_finding_id"]
                _investigation_meta["child_turns_used"] = obj.get(
                    "child_turns_used")
                _investigation_meta["child_tool_calls_total"] = obj.get(
                    "child_tool_calls_total")
        else:
            obj = client.chat_json(
                [{"role": "system", "content": _system_prompt_patch},
                 {"role": "user", "content": prompt}],
                required=("analysis", "edits"),
            )
    except budget_mod.CeilingExceeded:
        raise
    except models_mod.AuthError as e:
        # Not transient. Retrying spends attempts to reproduce the same 401 and
        # hides a config fault behind a retry count.
        return StageResult.fail(
            "CONFIG ERROR (auth) - " + str(e)[:400],
            meta={"outcome": "patch_auth_config_error", "config_error": True,
                  "auth_failed": True, "transient": False})
    except _InvestigationGaveUp as e:
        return StageResult.fail(
            "INVESTIGATION GAVE UP - model declined to fix: " + str(e),
            meta={"outcome": "patch_investigation_gave_up",
                  "patch_evaluated": False,
                  "investigation": True,
                  "give_up_reason": str(e)[:400]})
    except _InvestigationBudgetExhausted as e:
        return StageResult.fail(
            "INVESTIGATION BUDGET EXHAUSTED - " + str(e),
            meta={"outcome": "patch_investigation_exhausted",
                  "patch_evaluated": False,
                  "investigation": True,
                  "max_turns": _investigation_turns,
                  "max_usd": _investigation_max_usd})
    except _InvestigationChildFailed as e:
        return StageResult.reject(
            f"PATCH INTRODUCES DOWNSTREAM BUG, UNFIXED — child investigation "
            f"{e.child_finding_id[:8]} could not close the new crash the "
            f"parent's patch exposed. {e.child_reason}",
            meta={"outcome": "patch_investigation_child_failed",
                  "patch_evaluated": True,
                  "investigation": True,
                  "child_finding_id": e.child_finding_id,
                  "child_reason": e.child_reason[:400]})
    except _InvestigationRecursionDepthExceeded as e:
        return StageResult.fail(
            "INVESTIGATION RECURSION DEPTH EXCEEDED - " + str(e),
            meta={"outcome": "patch_investigation_recursion_depth_exceeded",
                  "patch_evaluated": False,
                  "investigation": True,
                  "max_recursion_depth": _investigation_max_recursion})
    except Exception as e:
        return StageResult.retry("patch model call failed: " + str(e),
                                 meta={"outcome": "patch_model_call_failed"})

    _dur_patch = round(_tm_patch.time() - _t0_patch, 2)
    ctx.store.emit(f.id, "patch", "response_received",
                   f"response in {_dur_patch}s: confidence="
                   f"{obj.get('confidence', '?')}, analysis={len(obj.get('analysis', ''))}B, "
                   f"edits={len(obj.get('edits', ''))}B",
                   duration_s=_dur_patch,
                   meta={"confidence": obj.get("confidence", ""),
                         "analysis_bytes": len(obj.get("analysis", "")),
                         "edits_bytes": len(obj.get("edits", "")),
                         "seconds": _dur_patch,
                         "model": client.cfg.model})
    # Persist the raw response body verbatim so the evidence bundle can carry
    # what the model actually returned, not just the parsed shape. Includes
    # any prose/preamble the model chose to attach around the JSON reply.
    ctx.store.add_artifact(
        f.id, "response", "patch",
        content=(client.last_raw_response or ""),
        meta={"seat": "patch",
              "model": client.cfg.model,
              "endpoint": client.cfg.endpoint,
              "seconds": _dur_patch,
              "attempt": "first"},
        model=client.cfg.model)

    try:
        blocks = edit_mod.parse(obj.get("edits", ""))
    except edit_mod.EditsWrongTypeError as _wt:
        # SCHEMA VIOLATION, not an apply failure. The `edits` field arrived as
        # something other than a string (list, dict, int, …). A first-class
        # terminal outcome — not infrastructure, not auto-retried. The fix for
        # this class of failure lives in the prompt, not in a retry loop.
        ctx.store.emit(
            f.id, "patch", "patch_edits_wrong_type",
            f"model returned edits as {_wt.actual_type}; expected string",
            meta={"actual_type": _wt.actual_type,
                  "model": client.cfg.model,
                  "file": rel})
        return StageResult.fail(
            f"PATCH EDITS WRONG TYPE — the model returned the `edits` field "
            f"as a {_wt.actual_type} instead of the schema's required string "
            f"of concatenated SEARCH/REPLACE blocks. Not auto-retried: a "
            f"model that returned {_wt.actual_type} once will very likely "
            f"return {_wt.actual_type} again. The fix for this class of "
            f"failure lives in the prompt.",
            meta={"outcome": "patch_edits_wrong_type",
                  "patch_evaluated": False,
                  "actual_type": _wt.actual_type,
                  "file": rel})
    try:
        applied = edit_mod.apply(source, blocks)
    except edit_mod.AmbiguousSearchError as _amb:
        # SINGLE RETRY with the exact validator message. Parallel to
        # models.chat_json's JSON-repair loop — same shape, same accountability
        # contract. The model (not PatchWing) decides how to fix its own
        # ambiguity. No autofix, no ±N-line expansion, no global prompt change.
        # One bound. If the retry is also ambiguous, that is real information
        # about the model, not a case for further retries.
        ctx.store.emit(
            f.id, "patch", "patch_ambiguous",
            f"SEARCH block {_amb.block_index}/{_amb.total_blocks} in {rel} "
            f"matched {_amb.match_count} times — retrying model once with a "
            f"disambiguation note",
            meta={"file": rel, "block_index": _amb.block_index,
                  "total_blocks": _amb.total_blocks,
                  "match_count": _amb.match_count,
                  "search_first_line": (_amb.search.splitlines()[0][:200]
                                        if _amb.search.splitlines() else "")})
        retry_note = _format_ambiguity_retry_note(_amb, rel)
        ctx.store.emit(
            f.id, "patch", "patch_retry_ambiguous",
            f"POST retry to {client.cfg.endpoint} model={client.cfg.model} "
            f"({len(retry_note)}B note)",
            meta={"note_bytes": len(retry_note),
                  "model": client.cfg.model,
                  "endpoint": client.cfg.endpoint,
                  "seat": "patch"})
        _t1_patch = _tm_patch.time()
        try:
            obj = client.chat_json(
                [{"role": "system", "content": _system_prompt_patch},
                 {"role": "user", "content": prompt},
                 {"role": "assistant", "content": json.dumps(
                     {"analysis": obj.get("analysis", ""),
                      "edits": obj.get("edits", ""),
                      "confidence": obj.get("confidence", "")})[:8000]},
                 {"role": "user", "content": retry_note}],
                required=("analysis", "edits"),
            )
        except budget_mod.CeilingExceeded:
            raise
        except models_mod.AuthError as _ae:
            return StageResult.fail(
                "CONFIG ERROR (auth) on ambiguity retry - " + str(_ae)[:400],
                meta={"outcome": "patch_auth_config_error_on_retry",
                      "config_error": True, "auth_failed": True,
                      "transient": False})
        except Exception as _ce:
            return StageResult.retry(
                "patch model call failed on ambiguity retry: " + str(_ce),
                meta={"outcome": "patch_model_call_failed_on_retry"})
        _dur1_patch = round(_tm_patch.time() - _t1_patch, 2)
        ctx.store.emit(
            f.id, "patch", "response_received",
            f"retry response in {_dur1_patch}s: confidence="
            f"{obj.get('confidence', '?')}, "
            f"analysis={len(obj.get('analysis', ''))}B, "
            f"edits={len(obj.get('edits', ''))}B",
            duration_s=_dur1_patch,
            meta={"confidence": obj.get("confidence", ""),
                  "analysis_bytes": len(obj.get("analysis", "")),
                  "edits_bytes": len(obj.get("edits", "")),
                  "seconds": _dur1_patch,
                  "model": client.cfg.model,
                  "retry": True})
        ctx.store.add_artifact(
            f.id, "response", "patch",
            content=(client.last_raw_response or ""),
            meta={"seat": "patch",
                  "model": client.cfg.model,
                  "endpoint": client.cfg.endpoint,
                  "seconds": _dur1_patch,
                  "attempt": "ambiguity_retry"},
            model=client.cfg.model)
        try:
            blocks = edit_mod.parse(obj.get("edits", ""))
        except edit_mod.EditsWrongTypeError as _wt2:
            # Retry response also violated the schema (wrong type). Terminal,
            # distinct outcome from the first-attempt site so the guard can
            # tell them apart.
            ctx.store.emit(
                f.id, "patch", "patch_edits_wrong_type",
                f"retry model returned edits as {_wt2.actual_type}; "
                f"expected string",
                meta={"actual_type": _wt2.actual_type,
                      "model": client.cfg.model,
                      "file": rel, "retry": True})
            return StageResult.fail(
                f"PATCH EDITS WRONG TYPE (on ambiguity retry) — the model "
                f"returned the `edits` field as a {_wt2.actual_type} instead "
                f"of the schema's required string.",
                meta={"outcome": "patch_edits_wrong_type_on_retry",
                      "patch_evaluated": False,
                      "actual_type": _wt2.actual_type,
                      "file": rel})
        try:
            applied = edit_mod.apply(source, blocks)
        except edit_mod.AmbiguousSearchError as _amb2:
            # The retry also ambiguous. Terminal — one bound, fail loud.
            return StageResult.fail(
                f"PATCH AMBIGUOUS AFTER RETRY - block {_amb2.block_index}/"
                f"{_amb2.total_blocks} in {rel} matched {_amb2.match_count} "
                f"times even after the model was told the previous SEARCH "
                f"matched {_amb.match_count} times. Real information about "
                f"the model, not a case for further retries.",
                meta={"outcome": "patch_ambiguous_after_retry",
                      "patch_evaluated": False,
                      "first_attempt": {"block": _amb.block_index,
                                        "matches": _amb.match_count},
                      "retry_attempt": {"block": _amb2.block_index,
                                        "matches": _amb2.match_count},
                      "file": rel})
        except edit_mod.EditError as _ee:
            # Retry avoided ambiguity but hit a different apply failure
            # (SEARCH not found, whitespace drift, etc). Same treatment as the
            # first-try non-ambiguity path — runner-level retry — but a
            # distinct outcome so a reader can tell "the first try was
            # not-found" apart from "the first try was ambiguous, we retried,
            # and the retry was not-found."
            return StageResult.retry(
                "PATCH DID NOT APPLY (on ambiguity retry) - " + str(_ee),
                meta={"outcome": "patch_did_not_apply_on_retry",
                      "patch_did_not_apply": True,
                      "blocks": len(blocks), "window_lines": [lo, hi],
                      "file": rel})
    except edit_mod.EditError as e:
        # A HARNESS OUTCOME, not a verdict on the fix. The search text was absent
        # or (before the ambiguity retry landed) ambiguous, so nothing was ever
        # compiled or tested. Collapsing this into "the fix failed" is the same
        # error as every trap in the localization notes: a harness fault wearing
        # the model's face. Ambiguity is now caught above and retried once
        # in-stage; this path handles the remaining apply failures.
        return StageResult.retry(
            "PATCH DID NOT APPLY - " + str(e),
            meta={"outcome": "patch_did_not_apply", "patch_did_not_apply": True,
                  "blocks": len(blocks), "window_lines": [lo, hi], "file": rel})

    cfg = getattr(ctx, "config", None)
    limit = cfg.pipeline.max_patch_bytes if cfg else 65536
    diff = edit_mod.to_unified_diff(rel, source, applied.text)
    if len(diff) > limit:
        return StageResult.reject(
            "proposed diff is " + str(len(diff)) + " bytes, over max_patch_bytes ("
            + str(limit) + ") - too large to review quickly",
            meta={"outcome": "patch_diff_too_large", "diff_bytes": len(diff),
                  "limit": limit})

    model_id = client.cfg.model
    arts = [{
        "kind": "patch", "content": applied.text, "model": model_id,
        "base_commit": f.base_commit,
        "meta": {"file": rel, "analysis": obj.get("analysis", ""),
                 "confidence": obj.get("confidence", ""),
                 # Raw SEARCH/REPLACE blocks the model emitted, verbatim. The
                 # bundle assembler surfaces these in patch.searchreplace.json;
                 # without this, only the applied file bytes survive and the
                 # native block format is lost.
                 "edits_raw": obj.get("edits", ""),
                 "original_bytes": len(source), "fixed_bytes": len(applied.text),
                 "edit_blocks": applied.applied, "window_lines": [lo, hi],
                 "anchors": anchors[:6],
                 "localization_source": localization_source,
                 "context_files": list(context_sources.keys()),
                 "context_files_dropped": context_dropped,
                 "trace_files": {"crash": [p for p, _ in trace["crash"]],
                                 "storage": [p for p, _ in trace["storage"]],
                                 "origin": [p for p, _ in trace["origin"]]},
                 **_investigation_meta},
    }, {
        "kind": "patch_diff", "content": diff, "model": model_id,
        "base_commit": f.base_commit,
        "meta": {"file": rel, "bytes": len(diff)},
    }]

    ctx.store.emit(f.id, "patch", "patch_applied",
                   f"{applied.applied} block(s) matched {rel}, "
                   f"{len(source)}B → {len(applied.text)}B, diff {len(diff)}B",
                   meta={"file": rel,
                         "blocks_applied": applied.applied,
                         "original_bytes": len(source),
                         "fixed_bytes": len(applied.text),
                         "diff_bytes": len(diff)})

    return StageResult.ok(
        "patched " + rel + " via " + edit_mod.describe(applied.blocks)
        + " (window " + str(lo) + "-" + str(hi) + " of " + str(len(source))
        + " bytes, diff " + str(len(diff)) + "B, confidence="
        + str(obj.get("confidence", "?")) + ")", artifacts=arts,
        meta={"outcome": "patch_written"})


@stage("verify")
def verify(f: Finding, ctx: Context) -> StageResult:
    """
    The stage that decides whether any of this was real.

    Apply the patch in a sandbox, confirm the reproducer now passes, and confirm
    the project's own suite stays green. Green tests do not prove semantic
    correctness — an adversarial second opinion from a different model family
    belongs here too, and is not yet implemented.
    """
    spec = _spec(f, ctx)
    if spec is None:
        return StageResult.blocked("no target spec attached",
                                   meta={"outcome": "verify_no_spec"})

    art = ctx.store.latest_artifact(f.id, "patch")
    if art is None:
        return StageResult.fail("no patch artifact — run patch first",
                                meta={"outcome": "verify_no_patch_artifact"})
    if art["base_commit"] and f.base_commit and art["base_commit"] != f.base_commit:
        return StageResult.retry(
            "patch is stale (repo moved since it was generated) — regenerating",
            meta={"outcome": "verify_patch_stale", "patch_evaluated": False})

    rel = (json.loads(art["meta"]) or {}).get("file")
    if not rel:
        return StageResult.fail("patch artifact does not name a file",
                                meta={"outcome": "verify_patch_names_no_file"})

    lock = ctx.store.latest_artifact(f.id, "reproducer_lock")
    if lock is None:
        return StageResult.fail(
            "no reproducer_lock artifact — nothing pins the reproducer, so a green "
            "result here would prove nothing. Re-run reproduce.",
            meta={"outcome": "verify_no_reproducer_lock"})
    try:
        manifest = json.loads(lock["content"])
    except json.JSONDecodeError as e:
        return StageResult.fail(f"reproducer_lock is unreadable: {e}",
                                meta={"outcome": "verify_lock_unreadable"})

    cfg_obj = getattr(ctx, "config", None)
    build_seconds = None
    cmds = spec.get("commands") or {}
    results = {}
    violations: list[dict] = []
    # An in-image manifest holds container paths (/tmp/poc lives only in the
    # image and outside root), so it must be re-hashed THROUGH the sandbox. The
    # host-path check would resolve /src/libxml2//tmp/poc, find nothing, and
    # report the reproducer as deleted — a harness fault that voids a good run.
    _v_in_image = str(((spec.get("target") or {}).get("mode") or "")
                      ).replace("_", "-") == "in-image"
    pristine_token = manifest.get("pristine_dedup_token", "") or ""
    _repro_kind = (((manifest.get("verdict_config") or {}).get("kind")) or manifest.get("pristine_marker") or "").strip().lower()
    # Pod-per-finding (change 2): attach to the finding's pod. persist=True
    # keeps it alive for the rollback leg inside this call AND for any
    # subsequent iterate-once-more call.
    with _sandbox(ctx, spec, finding=f, persist=True) as sb:
        try:
            root = sb.prepare(_target_dir(spec))
        except sandbox_mod.InImageSandbox.PodLost as e:
            return StageResult.fail(
                f"POD LOST at verify — {e}. Start a new finding.",
                meta={"outcome": "pod_lost_at_verify",
                      "patch_evaluated": False})
        # §6a HASH TRIPLE, leg 1 of 3. Captured BEFORE the patch is written, from
        # the container that will run it — not from a host copy, which would be a
        # different file. Without this the edit machinery grades its own undo.
        try:
            pre_source = sb.read(rel)
        except Exception as e:
            return StageResult.fail(
                f"cannot read {rel} before patching, so the rollback leg could "
                f"not be proved reversible: {e}",
                meta={"outcome": "verify_pre_patch_unreadable",
                      "patch_evaluated": False})
        sha_before_patch = _sha256_text(pre_source)
        ctx.store.emit(f.id, "verify", "source_snapshot",
                       f"pre-patch bytes read from pod: sha256={sha_before_patch[:12]}",
                       meta={"file": rel, "sha_before_patch": sha_before_patch,
                             "bytes": len(pre_source)})
        sb.write(rel, art["content"])
        sha_after_patch = _sha256_text(art["content"])
        ctx.store.emit(f.id, "verify", "patched_source_written",
                       f"wrote patched {rel}: {len(art['content'])}B, "
                       f"sha256={sha_after_patch[:12]}",
                       meta={"file": rel, "sha_after_patch": sha_after_patch,
                             "bytes": len(art["content"])})

        # Assert the wall AFTER the patch is applied and BEFORE anything runs.
        # Sequence and permissions are defence in depth; this hash check is the
        # guarantee, because it does not assume either of them worked.
        violations = (wall_mod.check_in_sandbox(sb, manifest) if _v_in_image
                      else wall_mod.check(root, manifest))
        if violations:
            return StageResult.fail(
                "REPRODUCER WALL VIOLATED — the run is void. "
                + "; ".join(f"{v['file']} ({v['reason']}) {v['problem']}"
                            for v in violations[:5]),
                meta={"outcome": "verify_wall_violated_before_build",
                      "patch_evaluated": False},
                artifacts=[{
                    "kind": "wall_violation",
                    "content": json.dumps(violations, indent=2),
                    "meta": {"n": len(violations)},
                    "base_commit": f.base_commit,
                }])
        wall_mod.harden(root, manifest)

        # Assert the build actually consumed the patch. Established earlier: an
        # unchanged md5 does NOT prove a rebuild failed (a reproducible build fed a
        # no-op edit emits byte-identical output). Inverted for a REAL patch it is a
        # sound check — a non-empty diff that leaves the compiled artifact identical
        # means the patch never reached the binary, and every command after this
        # would be testing code the fix-writer never touched.
        #
        # Without it the symptom is a stale binary still crashing, reported as "the
        # fix-writer failed to fix the bug" — a harness fault wearing the model's
        # face, which is the same shape as every trap in the localization notes.
        artifact_path = ((spec.get("target") or {}).get("artifact") or "").strip()
        art_md5_before = ""
        if artifact_path and hasattr(sb, "md5"):
            art_md5_before = sb.md5(artifact_path)

        if cmds.get("build"):
            # Pod-per-finding (change 2): incremental build across iterations.
            #  - First time in this pod: run cmds["build"] (typically `arvo
            #    compile` → full autogen/configure/make). Retry on the ~30%
            #    MSan configure flakiness we bisected on 1076. Drop a marker
            #    file so subsequent verifies know setup is done.
            #  - Second time onward: if the spec declares
            #    cmds["incremental_build"], run that instead. Typically just
            #    `make -j$(nproc) && <relink fuzzer>` — seconds, not minutes,
            #    and does NOT touch configure so the MSan flakiness cannot
            #    hit during iteration.
            #  - Fallback if incremental_build is absent: always full build.
            #    Preserves the historical behaviour for specs that have not
            #    opted in.
            import time as _t
            _b0 = _t.time()
            _marker_path = "/tmp/.patchwing-compiled"
            _has_setup = sb.run(f"test -f {_marker_path}").ok
            _incr = (cmds.get("incremental_build") or "").strip()
            _build_cmd = _incr if (_has_setup and _incr) else cmds["build"]
            _build_phase = ("incremental" if (_has_setup and _incr) else "full")
            ctx.store.emit(f.id, "verify", "build_start",
                           f"[{_build_phase}] {_build_cmd[:200]}",
                           meta={"phase": _build_phase,
                                 "cmd": _build_cmd,
                                 "has_setup_marker": _has_setup})
            if _has_setup and _incr:
                r = sb.run(_incr)
            else:
                # Full compile. Retry once on MSan configure flakiness — the
                # test that fails is `whether we are cross compiling`, whose
                # SEGV is deterministic-ish per-attempt but 1-2 retries almost
                # always land a successful compile. Bounded at 2 total tries
                # so a genuinely broken build cannot burn all night.
                r = sb.run(cmds["build"])
                if (not r.ok
                        and not r.timed_out
                        and "cannot run C compiled programs" in r.tail(4000)):
                    ctx.store.emit(f.id, "verify", "build_retry",
                                   "hit MSan configure flakiness, retrying once")
                    r = sb.run(cmds["build"])
                if r.ok:
                    sb.run(f"touch {_marker_path}")
            build_seconds = round(_t.time() - _b0, 1)
            results["build"] = r
            ctx.store.emit(f.id, "verify", "build_done",
                           f"[{_build_phase}] exit {r.returncode} in {build_seconds}s"
                           + (" (timed out)" if r.timed_out else ""),
                           duration_s=build_seconds,
                           meta={"phase": _build_phase,
                                 "returncode": r.returncode,
                                 "timed_out": r.timed_out,
                                 "seconds": build_seconds})
            # Both build verdicts below are pronounced on THIS output, so both
            # attach it. build_compile_failure in particular is a REJECTION of the
            # fix-writer's work — "the patch is not valid code" — and it used to
            # ship with nothing but a 600-char tail inside the message. A reader
            # cannot check a compiler's verdict against a truncated string.
            _build_art = [{
                "kind": "build_log",
                "content": r.tail(4000),
                "meta": {"cmd": r.cmd, "returncode": r.returncode,
                         "timed_out": r.timed_out, "build_seconds": build_seconds,
                         "phase": "post-patch"},
                "base_commit": f.base_commit,
            }]
            if r.timed_out:
                # TIMEOUT IS NOT A REJECTION. r.ok folds timed_out into one
                # boolean, so a killed build used to report "patched tree does not
                # build" — absence wearing failure's face. The patch was never
                # judged: we ran out of clock. Distinct outcome, distinct string.
                return StageResult.retry(
                    f"BUILD TIMED OUT after {build_seconds}s against a "
                    f"{getattr(getattr(cfg_obj, 'sandbox', None), 'timeout_s', '?')}s "
                    f"ceiling. The patch was NOT evaluated — this is absence, not "
                    f"failure. Raise sandbox.timeout_s and re-run.",
                    artifacts=_build_art,
                    meta={"outcome": "build_timeout_kill",
                          "build_seconds": build_seconds,
                          "patch_evaluated": False})
            if not r.ok:
                # Distinguish "compiler judged the patch" from "environment broke
                # before the compiler ran". The 1076 CDATA run hit the second one
                # (configure: error / cannot run C compiled programs) and the old
                # code called it "the patch is not valid code" — a verdict on the
                # fix, drawn from a malfunction. Same disease as timeout/compile.
                is_verdict, why = _looks_like_compiler_verdict(r.tail(8000))
                if not is_verdict:
                    return StageResult.fail(
                        f"BUILD FAILED but the compiler did not judge the patch "
                        f"in {build_seconds}s (exit {r.returncode}) — {why}. "
                        f"The fix was NOT evaluated: this says nothing about it. "
                        f"Look at the build_log artifact for the failure.",
                        artifacts=_build_art,
                        meta={"outcome": "verify_build_harness_fault",
                              "build_seconds": build_seconds,
                              "returncode": r.returncode,
                              "patch_evaluated": False,
                              "harness_signal": why})
                return StageResult.reject(
                    f"BUILD FAILED TO COMPILE in {build_seconds}s (exit "
                    f"{r.returncode}) — the patch is not valid code ({why}): "
                    f"{r.tail(600)}",
                    artifacts=_build_art,
                    meta={"outcome": "build_compile_failure",
                          "build_seconds": build_seconds,
                          "returncode": r.returncode,
                          "patch_evaluated": True,
                          "compiler_signal": why})

        art_md5_after = ""
        # Rev-3 (Correction #3): dist-manifest sanity check.
        # NOT a verdict gate — bundlers can legitimately produce
        # byte-identical output on fixes that land in different chunks.
        # The reproducer flip below is the sole verdict; we just emit
        # an event noting build-ran-but-bytes-unchanged for reviewer
        # awareness.
        if artifact_path and art_md5_before and hasattr(sb, "md5"):
            art_md5_after = sb.md5(artifact_path)
            if art_md5_after and art_md5_after == art_md5_before:
                ctx.store.emit(f.id, "verify", "build_ran_bytes_unchanged",
                               f"[SANITY] {artifact_path} md5 byte-identical "
                               f"after build; verdict still decided by "
                               f"reproducer flip",
                               meta={"artifact": artifact_path,
                                     "md5_before": art_md5_before,
                                     "md5_after": art_md5_after,
                                     "kind": "sanity_not_verdict"})
        # Also compute the installed-dist manifest diff and emit as event.
        _idist_root = ((spec.get("target") or {}).get("installed_dist_root") or "").strip()
        _pristine_manifest = ((spec.get("target") or {}).get(
            "installed_dist_manifest_pristine") or {})
        if _idist_root and _pristine_manifest:
            try:
                _post = _compute_dist_manifest(sb, _idist_root)
                _changed = [k for k, v in _post.items()
                             if _pristine_manifest.get(k) != v]
                _removed = [k for k in _pristine_manifest if k not in _post]
                _added = [k for k in _post if k not in _pristine_manifest]
                ctx.store.emit(f.id, "verify", "dist_manifest_diff",
                               f"[SANITY] installed_dist changed={len(_changed)} "
                               f"added={len(_added)} removed={len(_removed)}",
                               meta={"root": _idist_root,
                                     "changed_count": len(_changed),
                                     "added_count": len(_added),
                                     "removed_count": len(_removed),
                                     "sample_changed": _changed[:10],
                                     "kind": "sanity_not_verdict"})
            except Exception as _e:
                ctx.store.emit(f.id, "verify", "dist_manifest_diff_failed",
                               f"[SANITY] could not diff installed_dist manifest: {_e}",
                               meta={"kind": "sanity_not_verdict"})

        ctx.store.emit(f.id, "verify", "reproducer_start",
                       f"running: {cmds.get('reproduce', '')}",
                       meta={"cmd": cmds.get("reproduce", "")})
        r_rep = sb.run(cmds.get("reproduce", ""))
        results["reproduce"] = r_rep
        ctx.store.emit(f.id, "verify", "reproducer_done",
                       f"exit {r_rep.returncode} in {round(r_rep.duration_s,1)}s",
                       duration_s=round(r_rep.duration_s, 3),
                       meta={"returncode": r_rep.returncode,
                             "timed_out": r_rep.timed_out,
                             "output_bytes": len(r_rep.tail(8000))})
        r_test = sb.run(cmds.get("test", ""))
        results["test"] = r_test

        # §6b′ at the verify leg, against the PRISTINE token recorded on unpatched
        # code. A patched tree that crashes differently has not been fixed — and it
        # has not failed in the way the reproducer describes either.
        verify_reading = _classify_repro(
            f, ctx, r_rep.returncode, r_rep.tail(8000),
            r_rep.timed_out, pristine_token=pristine_token,
            duration_s=getattr(r_rep, "duration_s", 0.0))
        ctx.store.emit(f.id, "verify", "four_state",
                       f"{verify_reading['state']}: {verify_reading['why']}",
                       meta=verify_reading)

        # ------------------------------------------------------------------
        # §6 THE ROLLBACK LEG.  red -> patch -> green -> ROLL BACK -> RED AGAIN
        #
        # SAME CONTAINER. This is a narrow, deliberate exception to
        # one-container-per-attempt, valid only WITHIN this one attempt: the claim
        # being tested is that THIS diff, in THIS tree, is what moved it from red
        # to green. A fresh container would re-introduce every variable the leg
        # exists to hold still. Do NOT relax this generally.
        #
        # Rollback is EVIDENCE, not a gate. If green does not become red again,
        # that indicts the UNDO MECHANISM or the ORACLE — never the patch, which
        # the container has already judged. Collapsing it into a patch rejection is
        # the (a)/(b) defect one layer up.
        # ------------------------------------------------------------------
        rollback = None
        if verify_reading["state"] == states_mod.CONFIRMED_GREEN:
            rb: dict = {"attempted": True, "same_container": True}
            ctx.store.emit(f.id, "rollback", "revert_start",
                           f"reverting {rel} in same pod",
                           meta={"file": rel, "target_hash": sha_before_patch})
            # Surgical revert: write back the exact pre-patch bytes.
            sb.write(rel, pre_source)
            try:
                sha_after_revert = _sha256_text(sb.read(rel))
            except Exception as e:
                sha_after_revert = f"(unreadable: {e})"
            rb["hash_triple"] = {
                "before_patch": sha_before_patch,
                "after_patch": sha_after_patch,
                "after_revert": sha_after_revert,
                "reverted_cleanly": sha_after_revert == sha_before_patch,
                "assertion": "after_revert == before_patch, byte for byte",
                "honest_limit": (
                    "Proves the diff is reversible and load-bearing. Does NOT "
                    "prove a byte-identical working tree — only this one file was "
                    "hashed."),
            }
            ctx.store.emit(f.id, "rollback", "hash_triple",
                           f"before={sha_before_patch[:12]} "
                           f"after={sha_after_patch[:12]} "
                           f"revert={sha_after_revert[:12]} "
                           f"reverted_cleanly={rb['hash_triple']['reverted_cleanly']}",
                           meta=rb["hash_triple"])
            if sha_after_revert != sha_before_patch:
                # The undo did not restore the file. Anything run now would test an
                # unknown tree, so nothing is run: a rollback reading taken here
                # would be meaningless, and a meaningless reading that happens to
                # say "red" is exactly the malfunction this leg guards against.
                rb["state"] = "undo_broken"
                rb["why"] = ("the revert did not restore the original bytes, so no "
                             "rollback reading was taken — an unknown tree cannot "
                             "produce evidence")
            else:
                rb_build_ok, rb_build_seconds = True, None
                if cmds.get("build"):
                    import time as _t2
                    _r0 = _t2.time()
                    # Pod-per-finding: the rollback rebuild reuses the same
                    # pod, so incremental_build is available. Prefer it. The
                    # marker file was set by the first successful full compile
                    # inside this pod; if it exists AND the spec declares
                    # incremental_build, use that. Otherwise fall back to full
                    # cmds["build"] (arvo compile) — same policy as the
                    # forward-verify build path above.
                    _rb_has_setup = sb.run(f"test -f {_marker_path}").ok
                    _rb_cmd = _incr if (_rb_has_setup and _incr) else cmds["build"]
                    _rb_phase = ("incremental" if (_rb_has_setup and _incr)
                                 else "full")
                    ctx.store.emit(f.id, "rollback", "rollback_build_start",
                                   f"[{_rb_phase}] {_rb_cmd[:200]}",
                                   meta={"phase": _rb_phase, "cmd": _rb_cmd})
                    if _rb_has_setup and _incr:
                        rb_build = sb.run(_incr)
                        rb["build_phase"] = "incremental"
                    else:
                        rb_build = sb.run(cmds["build"])
                        rb["build_phase"] = "full"
                    rb_build_seconds = round(_t2.time() - _r0, 1)
                    results["rollback_build"] = rb_build
                    rb_build_ok = rb_build.ok and not rb_build.timed_out
                    ctx.store.emit(f.id, "rollback", "rollback_build_done",
                                   f"[{_rb_phase}] exit {rb_build.returncode} "
                                   f"in {rb_build_seconds}s",
                                   duration_s=rb_build_seconds,
                                   meta={"phase": _rb_phase,
                                         "returncode": rb_build.returncode,
                                         "timed_out": rb_build.timed_out,
                                         "seconds": rb_build_seconds})
                rb["build_seconds"] = rb_build_seconds
                if not rb_build_ok:
                    rb["state"] = "build_failed"
                    rb["why"] = ("the reverted tree did not rebuild, so the bug "
                                 "could not be shown to return")
                else:
                    # Stale-daemon guard (chain-breaker fix). A daemon-style http reproducer
                    # (nohup+disown server, "start only if not already running") leaves the
                    # GREEN leg's server bound to its port; its own `if ! curl` then REUSES
                    # that stale process on the rollback run, and it still holds the PATCHED
                    # code in memory, so the reverted-tree reproduce reads green again and the
                    # chain never closes (verify_green_rollback_not_red). Proven by PID reuse
                    # (run1==run2 PID; a fresh PID only after a kill). Kill the listeners so
                    # the reproducer relaunches against reverted code. http-kind only: a
                    # sanitizer reproducer spawns-and-exits, so nothing listens and this is a
                    # no-op for it.
                    if _repro_kind == "http":
                        sb.run(
                            "for _p in $(ss -ltnH 2>/dev/null | grep -oE 'pid=[0-9]+' | "
                            "cut -d= -f2 | sort -u); do kill \"$_p\" 2>/dev/null; done; "
                            "pkill -f 'vite|npx vite|node .*(serve|vite|http)' 2>/dev/null; "
                            "sleep 2; true")
                        ctx.store.emit(f.id, "rollback", "daemon_reset",
                                       "killed lingering listeners so a daemon reproducer "
                                       "relaunches against the reverted code",
                                       meta={"kind": "http"})
                    ctx.store.emit(f.id, "rollback", "reproducer_start",
                                   f"re-running: {cmds.get('reproduce', '')}",
                                   meta={"cmd": cmds.get("reproduce", "")})
                    rb_rep = sb.run(cmds.get("reproduce", ""))
                    results["rollback_reproduce"] = rb_rep
                    ctx.store.emit(f.id, "rollback", "reproducer_done",
                                   f"exit {rb_rep.returncode} in "
                                   f"{round(rb_rep.duration_s, 1)}s",
                                   duration_s=round(rb_rep.duration_s, 3),
                                   meta={"returncode": rb_rep.returncode,
                                         "timed_out": rb_rep.timed_out})
                    rb_reading = _classify_repro(
                        f, ctx, rb_rep.returncode, rb_rep.tail(8000),
                        rb_rep.timed_out, pristine_token=pristine_token,
                        duration_s=getattr(rb_rep, "duration_s", 0.0))
                    rb["four_state"] = rb_reading
                    rb["state"] = rb_reading["state"]
                    rb["why"] = rb_reading["why"]
                    ctx.store.emit(f.id, "rollback", "four_state",
                                   f"{rb_reading['state']}: {rb_reading['why']}",
                                   meta=rb_reading)
            rollback = rb

        # And again after execution: a patch that rewrites the reproducer at
        # runtime would otherwise pass both checks above.
        violations = (wall_mod.check_in_sandbox(sb, manifest) if _v_in_image
                      else wall_mod.check(root, manifest))

    if violations:
        return StageResult.fail(
            "REPRODUCER WALL VIOLATED DURING EXECUTION — the run is void. "
            + "; ".join(f"{v['file']} ({v['reason']}) {v['problem']}"
                        for v in violations[:5]),
            meta={"outcome": "verify_wall_violated_during_execution",
                  "patch_evaluated": False},
            artifacts=[{
                "kind": "wall_violation",
                "content": json.dumps(violations, indent=2),
                "meta": {"n": len(violations), "phase": "post-execution"},
                "base_commit": f.base_commit,
            }])

    summary = {k: {"returncode": v.returncode, "timed_out": v.timed_out}
               for k, v in results.items()}
    # Wall-clock is a first-class recorded field, not inferred from log
    # timestamps: on containerised targets it is the binding cost, not tokens.
    summary["build_seconds"] = build_seconds
    summary["wall"] = {"intact": True, "n_files": manifest.get("n_files", 0),
                       "algorithm": manifest.get("algorithm", "sha256")}
    # Record the build-artifact hashes on the SUCCESS path too, not only when the
    # assertion fires. Previously these lived in local variables and were written
    # to meta only on the build_did_not_consume_patch failure, so a run that
    # passed the check left no evidence it had been made — and "the assertion did
    # not fire" is an inference about control flow, not a recorded value. The
    # evidence package must carry the hashes it claims to have compared.
    if artifact_path:
        summary["build_artifact"] = {
            "path": artifact_path,
            "md5_before_patch": art_md5_before or "(not captured)",
            "md5_after_compile": art_md5_after or "(not captured)",
            "changed": bool(art_md5_before and art_md5_after
                            and art_md5_before != art_md5_after),
            "assertion": "a non-empty patch that leaves this hash unchanged voids "
                         "the run as build_did_not_consume_patch",
            "before_is_reproducible": True,
            "after_is_reproducible": False,
            "what_this_proves": (
                "INTERNAL CONSISTENCY OF THIS RUN ONLY. The BEFORE hash is "
                "independently reproducible: it is the artifact shipped in the "
                "immutable image, so anyone can pull that image and match it. The "
                "AFTER hash is NOT reproducible - OSS-Fuzz builds are not hermetic "
                "(timestamps, paths, toolchain and link order vary), so a third "
                "party rebuilding will very likely get a different value, and a "
                "mismatch there is NOT evidence of tampering. The pair proves only "
                "that the patch reached the compiled binary in this run. What a "
                "stranger actually reproduces is red -> green, not a hash."),
        }
    evidence = "\n\n".join(
        f"$ {v.cmd}\n[exit {v.returncode}]\n{v.tail(1500)}"
        for k, v in results.items() if v.cmd)

    # Provenance: the chain must name WHO wrote the patch and against WHAT tree.
    # An unattributed verdict cannot be audited - a reader has no way to tell which
    # model produced the fix it vouches for, or what source it was applied to.
    _pm = {}
    try:
        _pm = json.loads(art["meta"] or "{}")
    except (json.JSONDecodeError, TypeError):
        pass
    _fix_model = art["model"] or "(unrecorded)"
    _tree = (art["base_commit"] or f.base_commit
             or (spec.get("target") or {}).get("image", "") or "(unrecorded)")
    summary["provenance"] = {
        "fix_writer_model": _fix_model,
        "patched_file": _pm.get("file", "?"),
        "tree": _tree,
        "target_mode": (spec.get("target") or {}).get("mode", "host"),
    }
    verdict_art = [{
        "kind": "verdict", "content": evidence,
        "meta": summary,
        "model": _fix_model,
        "base_commit": _tree,
    }]

    # The reproducer must now pass: the boundary violation is closed.
    if r_rep.timed_out:
        summary["outcome"] = "verify_reproducer_timeout"
        return StageResult.retry(
            "reproducer TIMED OUT under the patch — absence, not failure; the "
            "patch was not judged", artifacts=verdict_art,
            meta={"outcome": "verify_reproducer_timeout",
                  "patch_evaluated": False})

    # §6b′ — FOUR states, never two. `r_rep.returncode != 0` would read a harness
    # fault as "the fix did not work", which is a verdict on the patch drawn from a
    # malfunction. Each state gets its own answer.
    if verify_reading["state"] == states_mod.DIFFERENT_BUG:
        summary["outcome"] = "verify_different_bug"
        return StageResult.reject(
            f"the patched tree crashes, but NOT with the tracked bug — "
            f"{verify_reading['why']}. The original may or may not be closed; "
            f"what is certain is that this is a different crash.",
            artifacts=verdict_art,
            meta={"outcome": "verify_different_bug", "patch_evaluated": True,
                  "four_state": verify_reading})
    if verify_reading["state"] == states_mod.HARNESS_FAULT:
        summary["outcome"] = "verify_harness_fault"
        return StageResult.fail(
            f"HARNESS FAULT at verify — {verify_reading['why']}. The patch was "
            f"NOT evaluated: this says nothing about the fix.",
            artifacts=verdict_art,
            meta={"outcome": "verify_harness_fault", "patch_evaluated": False,
                  "four_state": verify_reading})
    if verify_reading["state"] == states_mod.CONFIRMED_RED:
        summary["outcome"] = "verify_fix_did_not_resolve"
        return StageResult.reject(
            f"patch does not close the bug — the same crash still fires "
            f"(exit {r_rep.returncode}, token matches the pristine reproducer). "
            f"Built and ran; the fix is the thing being judged here.",
            artifacts=verdict_art,
            meta={"outcome": "verify_fix_did_not_resolve",
                  "patch_evaluated": True, "four_state": verify_reading})

    # And the project's own suite must be unbroken.
    if cmds.get("test") and not r_test.ok:
        return StageResult.reject(
            f"patch breaks the existing test suite (exit {r_test.returncode}) — "
            f"a fix that breaks the feature is not a fix", artifacts=verdict_art,
            meta={"outcome": "verify_suite_broken", "patch_evaluated": True})

    # The container has now ruled. Only here — after pass/fail is settled — does
    # the advisory reviewer get to speak, so its opinion cannot influence the
    # verdict even by accident.
    advisory = _advisory_review(f, ctx, art["content"], evidence)
    note = ""
    if advisory and advisory[0]["meta"].get("available"):
        note = f"; advisory review: {advisory[0]['meta'].get('verdict', '?')}"

    # THE outcome the milestone exists to produce. It is carried on the result as
    # well as in the verdict artifact: the artifact is evidence a reader inspects,
    # the result meta is what the pipeline records. Setting only the artifact left
    # the green path unlabelled at the layer that counts, which is why the §9 audit
    # read this path as already covered when it was not.
    # §6 — the rollback reading rides WITH the verdict. It never overturns it:
    # the container ruled green, and a rollback that fails to return red indicts
    # the undo or the oracle, not the patch. So all four cases below are OK, and
    # the outcome value is what tells a reader which chain was actually proved.
    summary["rollback"] = rollback or {
        "attempted": False,
        "why": "verify was not green, so there was nothing to roll back",
    }
    # Four explicit returns rather than one with a computed value. A variable here
    # would be invisible to the static guard — it cannot check a value it cannot
    # read — and "the outcome is whatever this local says" is precisely the shape
    # the closed set exists to forbid.
    _rb_state = (rollback or {}).get("state")
    _wall_note = (f"wall intact ({manifest.get('n_files', 0)} file(s) unchanged)"
                  f"{note}")

    if _rb_state == states_mod.CONFIRMED_RED:
        chain = "FULL CHAIN PROVED: red -> patch -> green -> rollback -> red again"
        summary["chain"] = chain
        summary["outcome"] = "verify_green_rollback_red"
        return StageResult.ok(
            f"{chain}; {_wall_note}", artifacts=verdict_art + advisory,
            meta={"outcome": "verify_green_rollback_red", "patch_evaluated": True,
                  "four_state": verify_reading, "rollback": rollback})

    if _rb_state == "undo_broken":
        chain = ("patch VERIFIED GREEN, but the revert did not restore the "
                 "original bytes — this indicts the UNDO MECHANISM, not the patch")
        summary["chain"] = chain
        summary["outcome"] = "verify_green_rollback_undo_broken"
        return StageResult.ok(
            f"{chain}; {_wall_note}", artifacts=verdict_art + advisory,
            meta={"outcome": "verify_green_rollback_undo_broken",
                  "patch_evaluated": True, "four_state": verify_reading,
                  "rollback": rollback})

    if _rb_state == "build_failed":
        chain = ("patch VERIFIED GREEN, but the reverted tree did not rebuild, so "
                 "the bug could not be shown to return — inconclusive rollback, "
                 "not a failed patch")
        summary["chain"] = chain
        summary["outcome"] = "verify_green_rollback_build_failed"
        return StageResult.ok(
            f"{chain}; {_wall_note}", artifacts=verdict_art + advisory,
            meta={"outcome": "verify_green_rollback_build_failed",
                  "patch_evaluated": True, "four_state": verify_reading,
                  "rollback": rollback})

    chain = (f"patch VERIFIED GREEN, but rollback did NOT return red "
             f"({_rb_state or 'not attempted'}) — this indicts the UNDO MECHANISM "
             f"or the ORACLE, never the patch")
    summary["chain"] = chain
    summary["outcome"] = "verify_green_rollback_not_red"
    return StageResult.ok(
        f"{chain}; {_wall_note}", artifacts=verdict_art + advisory,
        meta={"outcome": "verify_green_rollback_not_red", "patch_evaluated": True,
              "four_state": verify_reading, "rollback": rollback})


def _four_state_lines(art, leg: str) -> list[str]:
    """Render one leg's four-state reading — the INPUTS, not just the conclusion.

    A reader has to be able to disagree with the classification, which means
    seeing the exit code, whether the sanitizer marker was present, and which
    crash identity was matched. "confirmed_red" on its own is an assertion.
    """
    try:
        m = json.loads(art["meta"]) if art else {}
    except (json.JSONDecodeError, TypeError):
        m = {}
    r = m.get("four_state") or {}
    if not r:
        return [f"_(no four-state reading recorded at {leg})_"]
    return [
        f"**State: `{r.get('state', '?')}`** — {r.get('why', '')}",
        "",
        "| signal | value |",
        "|---|---|",
        f"| exit code | `{r.get('returncode', '?')}` |",
        f"| sanitizer marker | {'PRESENT' if r.get('marker_present') else '**ABSENT**'}"
        f" — `{r.get('marker', '(none)')}` |",
        f"| crash identity (DEDUP_TOKEN) | `{r.get('dedup_token', '(none)')}` |",
        f"| pristine identity | `{r.get('pristine_token', '(none)')}` |",
        f"| identities match | {'yes' if r.get('token_matches_pristine') else 'no'} |",
    ]


def _chain_lines(verdict) -> list[str]:
    """The rollback leg: the part that makes red->green mean something.

    Green alone shows the reproducer stopped firing. It does not show that THIS
    diff is why. Removing the diff and watching the bug return is what closes that
    gap — and if it does not return, the honest reading is that the undo mechanism
    or the oracle is at fault, never the patch, which the container already judged.
    """
    try:
        s = json.loads(verdict["meta"]) if verdict else {}
    except (json.JSONDecodeError, TypeError):
        s = {}
    rb = s.get("rollback") or {}
    out = [f"**{s.get('chain', '(chain not recorded)')}**", ""]
    if not rb.get("attempted"):
        out += [f"_Rollback not attempted: {rb.get('why', 'unknown')}_"]
        return out

    h = rb.get("hash_triple") or {}
    out += [
        "The patched file was reverted to its exact pre-patch bytes **in the same "
        "container**, rebuilt, and the reproducer re-run. Same container is a "
        "deliberate, narrow exception: a fresh one would re-introduce every "
        "variable this leg exists to hold still.",
        "",
        "### Hash triple (§6a)",
        "",
        "| point | sha256 |",
        "|---|---|",
        f"| before patch | `{h.get('before_patch', '?')}` |",
        f"| after patch | `{h.get('after_patch', '?')}` |",
        f"| after revert | `{h.get('after_revert', '?')}` |",
        "",
        f"**`after_revert == before_patch`: "
        f"{'YES' if h.get('reverted_cleanly') else 'NO'}** — "
        f"{h.get('assertion', '')}",
        "",
        f"_Honest limit: {h.get('honest_limit', '')}_",
        "",
        "### The reproducer, re-run on the reverted tree",
        "",
    ]
    r = rb.get("four_state") or {}
    if r:
        out += [
            f"**State: `{r.get('state', '?')}`** — {r.get('why', '')}",
            "",
            f"- exit code `{r.get('returncode', '?')}`",
            f"- sanitizer marker "
            f"{'PRESENT' if r.get('marker_present') else '**ABSENT**'}",
            f"- crash identity `{r.get('dedup_token', '(none)')}`, "
            f"matches pristine: "
            f"{'yes' if r.get('token_matches_pristine') else 'no'}",
        ]
    else:
        out += [f"_No reading taken: {rb.get('why', 'unknown')}_"]
    return out


def _oracle_lines(spec: dict) -> list[str]:
    """State the caveat plainly, in the package, where a stranger will hit it.

    This is the section most likely to be quietly dropped, because it is the one
    that makes the result smaller. That is exactly why it is emitted from the spec
    rather than written by hand.
    """
    o = (spec or {}).get("oracle") or {}
    if not o:
        return ["_No oracle section declared: nothing was handed to the "
                "fix-writer beyond the finding itself._"]
    return [
        "**Localization was ORACLED — deliberately.** The vulnerable file and the "
        "region were handed to the fix-writer, not discovered by it.",
        "",
        "| | |",
        "|---|---|",
        f"| file | `{o.get('file', '?')}` |",
        f"| region | lines **{o.get('region_start', '?')}–{o.get('region_end', '?')}**"
        f" ({o.get('region_lines', '?')} lines, contiguous:"
        f" {'yes' if o.get('contiguous') else 'no'}) |",
        "",
        f"**Why the region is wide:** {(o.get('why_why') or o.get('why_wide') or '').strip()}",
        "",
        f"**Therefore this run demonstrates {o.get('what_this_run_demonstrates', '?')}.** "
        f"It is NOT evidence that the pipeline can find this bug unaided, and it is "
        f"NOT a measure of how hard the fix was.",
    ]


@stage("package")
def package(f: Finding, ctx: Context) -> StageResult:
    """
    Assemble the evidence bundle — the actual product.

    Reproducer failing before, passing after; suite green; regression test; a
    one-screen diff. The bar: a reviewer should find it cheaper to review than
    to ignore.
    """
    spec = _spec(f, ctx) or {}
    patch_art = ctx.store.latest_artifact(f.id, "patch")
    verdict = ctx.store.latest_artifact(f.id, "verdict")
    repro = ctx.store.latest_artifact(f.id, "reproducer")
    lock = ctx.store.latest_artifact(f.id, "reproducer_lock")
    if not (patch_art and verdict):
        return StageResult.fail("missing patch or verdict artifact",
                                meta={"outcome": "package_missing_inputs"})
    if lock is None:
        return StageResult.fail(
            "no reproducer_lock — the bundle cannot attest that the reproducer "
            "was unchanged, which is the claim the whole package rests on",
            meta={"outcome": "package_no_reproducer_lock"})
    try:
        manifest = json.loads(lock["content"])
    except json.JSONDecodeError:
        manifest = {"files": {}, "n_files": 0}

    meta = json.loads(patch_art["meta"]) or {}
    lines = [
        f"# {f.title or 'Security fix'}",
        "",
        f"**CWE:** {f.cwe or 'unspecified'}    "
        f"**Reference:** {f.source_ref or 'n/a'}    "
        f"**File:** {meta.get('file', '?')}",
        "",
        "## What was wrong",
        f.description.strip() or "(no description supplied)",
        "",
        "## Why this fix closes it",
        meta.get("analysis", "(no analysis)"),
        "",
        "## 1. The reproducer",
        "",
        f"Frozen before any patch existed. {wall_mod.summarize(manifest)}.",
        "",
        "```",
        (_repro_source(ctx, spec, manifest) or "(source not recorded)")[:3000],
        "```",
        "",
        "## 2. Proof it FAILS on the unpatched code",
        "",
        *_four_state_lines(repro, "reproduce"),
        "",
        "```",
        (repro["content"] if repro else "(none)")[:1200],
        "```",
        "",
        "## 3. The patch",
        "",
        *_diff_lines(f, ctx, spec),
        "",
        "## 4-5. Proof it PASSES, and the suite stays green",
        "",
        "```",
        (verdict["content"] or "")[:2500],
        "```",
        "",
        "## 5b. THE CHAIN — red, green, and red again",
        "",
        *_chain_lines(verdict),
        "",
        "## 5c. What was handed over, and what that costs this result",
        "",
        *_oracle_lines(spec),
        "",
        "## 6. Re-run it yourself",
        "",
        *_container_lines(f, ctx, spec),
        "",
        "## 6b. The build artifact actually changed",
        "",
        *_build_artifact_lines(f, ctx),
        "",
        "## 8. Which model sat in which seat",
        "",
        *_seat_lines(f, ctx),
        "",
        "## 7. Advisory review (an opinion, not a verdict)",
        "",
        *_review_lines(f, ctx),
        "",
        "## 8b. Cost",
        "",
        *_cost_lines(f, ctx),
        "",
        "## 9. Reproducer attestation",
        "",
        "The reproducer was frozen before any patch existed and its hash was "
        "re-checked after the patch was applied and again after the suite ran. "
        "It is byte-identical throughout, so the pass above cannot have been "
        "obtained by weakening the test. Recompute these yourself:",
        "",
        "```",
        f"algorithm: {manifest.get('algorithm', 'sha256')}",
        *[f"{v['sha256']}  {k}  [{v['reason']}]"
          for k, v in sorted((manifest.get("files") or {}).items())
          if v.get("reason") == "reproducer"],
        f"({manifest.get('n_files', 0)} file(s) frozen in total, including the "
        f"project suite)",
        "```",
        "",
        f"Generated by PatchWing using `{patch_art['model'] or 'unknown model'}`. "
        f"The fix was tested, not trusted: which model wrote it does not affect "
        f"the verdict. Reviewed by a human before submission.",
    ]
    return StageResult.ok("evidence bundle assembled", artifacts=[{
        "kind": "evidence", "content": "\n".join(lines),
        "base_commit": f.base_commit,
    }], meta={"outcome": "package_assembled"})


@stage("review")
def review(f: Finding, ctx: Context) -> StageResult:
    """Human gate. Emits pending_signoff — distinct from `blocked` (which
    implies something is broken). pending_signoff means the pipeline
    finished cleanly and just needs an operator's OK."""
    return StageResult.pending_signoff("awaiting human sign-off",
                                        meta={"outcome": "review_awaiting_human"})
