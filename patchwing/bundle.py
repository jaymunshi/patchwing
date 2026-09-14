"""Portable evidence bundle for a PatchWing finding — full dashboard parity.

Reads STRICTLY from the store — no pod touch, no model call, no reproducer
re-run. Produces a deterministic `.tar.gz` such that the same finding_id
yields a byte-identical archive on every invocation (mtime read from the
finding's `created_at`, never stamped fresh; tarfile members sorted; gzip
mtime fixed at 0).

Archive layout:

    evidence.md                     PatchWing's markdown, as stored
    manifest.json                   machine-readable provenance + counts
    finding.json                    full dashboard-parity dump
    patch.diff                      unified diff, git-apply-ready
    patch.searchreplace.json        raw SEARCH/REPLACE blocks the model emitted
    process-log.jsonl               every stage event, one JSON per line
    hashes.txt                      sha256 of every OTHER file in the bundle

    reproducer/poc                  reproducer input bytes (byte-identical)
    reproducer/run.sh               one-line invocation

    prompts/NNNN-{seat}-{model}.txt      full system+user body per model call
    responses/NNNN-{seat}-{model}.txt    full raw response body per call
    verdicts/NNNN-{seat}.json            one per verdict artifact
    advisory/NNNN-{seat}.{json|txt}      one per review_advisory artifact
    artifacts/{kind}-NNNN.{ext}          every raw artifact row's bytes
    spend/spend.jsonl                    live spend rows, JSONL
    spend/spend_prior.jsonl              demoted spend rows, JSONL
    traces/investigation.jsonl           one line per investigation turn

    container.txt                   image ref + digest (digest unknown here)
    README.md                       human-readable overview
    APPLY.md                        how to apply patch.diff to a dev checkout
    ROLLBACK.md                     how to revert
    apply.sh                        sha-checked git apply
    verify.sh                       run reproducer, exit non-zero if red
    rollback.sh                     sha-checked git apply -R

If any required artifact is missing from the store, listed under
`manifest.missing[]` with a reason; missing files are NOT written, but the
manifest still records exactly what wasn't there. Never fabricates or
substitutes.
"""
from __future__ import annotations

import base64
import datetime
import gzip
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass


PATCHWING_VERSION = "0.2.0"

REQUIRED_ARTIFACT_KINDS = (
    "spec",
    "patch",
    "patch_diff",
    "reproducer",
    "reproducer_input",
    "reproducer_lock",
    "verdict",
    "evidence",
)


class BundleAssemblyError(Exception):
    def __init__(self, missing: list[str], finding_id: str = ""):
        self.missing = list(missing)
        self.finding_id = finding_id
        super().__init__(
            f"cannot assemble bundle for {finding_id or '(unknown)'}: "
            f"missing: {', '.join(self.missing) if self.missing else '(none)'}")


@dataclass
class BundleResult:
    finding_id: str
    filename: str
    short_sha: str
    manifest_sha256: str
    bytes: bytes


# -- helpers ---------------------------------------------------------------

def _iso_utc(ts: float) -> str:
    return datetime.datetime.utcfromtimestamp(int(ts)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _artifact_bytes(art) -> bytes:
    c = art["content"]
    if isinstance(c, bytes):
        return c
    encoding = ""
    try:
        encoding = (json.loads(art["meta"] or "{}") or {}).get("encoding", "")
    except (json.JSONDecodeError, TypeError):
        pass
    if encoding == "base64":
        return base64.b64decode(c or "")
    return (c or "").encode("utf-8", errors="replace")


_MODEL_SLUG = re.compile(r"[^a-zA-Z0-9._-]+")


def _model_short(model: str) -> str:
    """Filesystem-safe short name from a model id."""
    if not model:
        return "unknown"
    tail = model.rsplit("/", 1)[-1]
    return _MODEL_SLUG.sub("-", tail).strip("-").lower() or "unknown"


def _parse_meta(row) -> dict:
    try:
        return json.loads(row["meta"] or "{}") or {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _row_to_dict(row) -> dict:
    d = {}
    for k in row.keys():
        v = row[k]
        d[k] = v
    return d


# -- manifest --------------------------------------------------------------

def _seats(store, finding_id: str) -> dict:
    seats: dict = {}
    for row in store.artifacts(finding_id, "spend"):
        m = _parse_meta(row)
        seat = m.get("seat", "")
        if seat and seat not in seats:
            seats[seat] = {"model": m.get("model", ""),
                           "endpoint": m.get("endpoint", "")}
    return seats


def _advisory_status(store, finding_id: str) -> tuple[dict | None, str, str]:
    """Return (seat_dict_or_None, status, reason).

    status is 'ok' when the advisory returned a verdict, 'unavailable' when
    the model call failed/timed out, or 'none' when no advisory artifact
    exists at all."""
    a = store.latest_artifact(finding_id, "review_advisory")
    if a is None:
        return None, "none", ""
    m = _parse_meta(a)
    rc = m.get("reviewer_config") or {}
    seat = {"model": rc.get("model", ""), "endpoint": rc.get("endpoint", "")}
    if m.get("available") is False:
        return seat, "unavailable", str(m.get("error", ""))[:400]
    return seat, "ok", ""


def _hash_triples_from_events(store, finding_id: str) -> list[dict]:
    """Collect every hash_triple event with stage + iteration index."""
    out = []
    per_stage_counts: dict[str, int] = {}
    for ev in store.events(finding_id):
        if ev["kind"] != "hash_triple":
            continue
        stage = ev["stage"] or ""
        per_stage_counts[stage] = per_stage_counts.get(stage, 0) + 1
        m = _parse_meta(ev)
        out.append({
            "stage": stage,
            "iteration": per_stage_counts[stage],
            "before": m.get("before_patch", ""),
            "after": m.get("after_patch", ""),
            "revert": m.get("after_revert", ""),
            "reverted_cleanly": bool(m.get("reverted_cleanly", False)),
        })
    return out


def _pod_events(store, finding_id: str) -> list[dict]:
    out = []
    for ev in store.events(finding_id):
        kind = ev["kind"] or ""
        if not (kind == "pod_ready" or kind.startswith("pod_")):
            continue
        m = _parse_meta(ev)
        out.append({
            "event": kind,
            "container_id": m.get("container_id", ""),
            "image": m.get("image", ""),
            "timestamp": ev["created_at"],
        })
    return out


def _wall_frozen(lock_meta: dict) -> list[dict]:
    files = (lock_meta.get("files") or {})
    out = []
    for path in sorted(files):
        entry = files[path] or {}
        out.append({"path": path,
                    "sha256": entry.get("sha256", ""),
                    "role": entry.get("reason", "")})
    return out


def _reproducer_sha_from_lock(lock_meta: dict) -> str:
    for _, entry in (lock_meta.get("files") or {}).items():
        if entry.get("reason") == "reproducer":
            return entry.get("sha256", "")
    return ""


def _binary_hashes(verdict_meta: dict) -> dict | None:
    """Extract the build-artifact md5 pair from the verdict summary if any."""
    ba = verdict_meta.get("build_artifact") or {}
    if not ba:
        return None
    before = ba.get("md5_before_patch", "")
    after = ba.get("md5_after_compile", "")
    if not before and not after:
        return None
    return {"before": before or None,
            "after": after or None,
            "path": ba.get("path", ""),
            "changed": bool(ba.get("changed", False))}


def _build_manifest(store, finding, artifacts, missing) -> tuple[bytes, str]:
    from . import budget as budget_mod

    spec = json.loads(artifacts["spec"]["content"] or "{}")
    target = spec.get("target") or {}
    patch_meta = _parse_meta(artifacts["patch"])
    verdict_meta = _parse_meta(artifacts["verdict"])
    lock_meta = json.loads(artifacts["reproducer_lock"]["content"] or "{}")
    triple = ((verdict_meta.get("rollback") or {}).get("hash_triple") or {})

    seats_map = _seats(store, finding.id)
    advisory_seat, advisory_status, advisory_reason = _advisory_status(
        store, finding.id)

    lifetime = budget_mod.total_lifetime(store, finding.id)

    # Counts + collections
    process_events = list(store.events(finding.id))
    prompt_arts = list(store.artifacts(finding.id, "prompt"))
    response_arts = list(store.artifacts(finding.id, "response"))
    verdict_arts = list(store.artifacts(finding.id, "verdict"))
    advisory_arts = list(store.artifacts(finding.id, "review_advisory"))
    all_arts = list(store.artifacts(finding.id))
    investigation_turn_events = [
        e for e in process_events if e["kind"] == "investigation_turn"]

    patched_file = patch_meta.get("file", "")
    verify_advisory_field: dict | None = seats_map.get("verify_advisory")
    if advisory_seat is not None and advisory_status == "ok":
        verify_advisory_field = advisory_seat
    elif advisory_status == "unavailable":
        verify_advisory_field = None

    # Post-review ARVO commentary (optional, always advisory-only).
    arvo_art = store.latest_artifact(finding.id, "arvo_comparison")
    if arvo_art is not None:
        arvo_meta = _parse_meta(arvo_art)
        arvo_block = {
            "present": True,
            "arvo_patch_sha256": arvo_meta.get("arvo_patch_sha256", ""),
            "our_patch_sha256": arvo_meta.get("our_patch_sha256", ""),
            "generated_at": arvo_meta.get("generated_at", ""),
            "note": arvo_meta.get(
                "note",
                "post-review commentary only; not a verdict; "
                "reproducer is the sole judge"),
            "origin": arvo_meta.get("origin", "OSS-Fuzz via ARVO"),
        }
    else:
        arvo_block = {
            "present": False,
            "arvo_patch_sha256": "",
            "our_patch_sha256": "",
            "generated_at": "",
            "note": ("post-review commentary only; not a verdict; "
                     "reproducer is the sole judge"),
            "origin": "OSS-Fuzz via ARVO",
        }

    manifest = {
        # existing fields ————————————————————————————————
        "arvo_comparison": arvo_block,
        "finding_id": finding.id,
        "parent_finding_id": finding.parent_finding_id or None,
        "cwe": finding.cwe or "",
        "reference": finding.source_ref or "",
        "created_at": _iso_utc(finding.created_at),
        "container_image": str(target.get("image", "")).strip(),
        "container_digest": None,
        "reproducer_sha256": _reproducer_sha_from_lock(lock_meta),
        "patch_sha256": _sha256(_artifact_bytes(artifacts["patch"])),
        "patched_file_paths": [patched_file] if patched_file else [],
        "model_seats": {
            "patch": seats_map.get("patch", {}),
            "verify_advisory": verify_advisory_field,
        },
        "advisory_status": advisory_status,
        "advisory_reason": advisory_reason,
        "chain_proof": {
            "before_sha256": triple.get("before_patch", ""),
            "after_sha256": triple.get("after_patch", ""),
            "revert_sha256": triple.get("after_revert", ""),
            "chain_proved": (
                bool(triple.get("reverted_cleanly", False))
                and triple.get("before_patch") != triple.get("after_patch")
            ),
        },
        "cost": {
            "tokens": lifetime.prompt_tokens + lifetime.completion_tokens,
            "usd": (round(lifetime.usd, 6) if lifetime.priced else None),
            "calls": lifetime.calls,
            "priced": lifetime.priced,
        },
        "patchwing_version": PATCHWING_VERSION,

        # new in v0.2 ——————————————————————————————————
        "process_log_events": len(process_events),
        "prompts": len(prompt_arts),
        "responses": len(response_arts),
        "investigation_turns": len(investigation_turn_events),
        "verdicts": len(verdict_arts),
        "advisories": len(advisory_arts),
        "artifacts": len(all_arts),
        "hash_triples": _hash_triples_from_events(store, finding.id),
        "pod_events": _pod_events(store, finding.id),
        "wall_frozen": _wall_frozen(lock_meta),
        "reproducer_lock": {
            "pristine_token": lock_meta.get("pristine_dedup_token", ""),
            "pristine_marker": lock_meta.get("pristine_marker", ""),
            "pristine_returncode": lock_meta.get("pristine_returncode"),
            "files": [
                {"path": p, "expected_sha256": (v or {}).get("sha256", "")}
                for p, v in sorted((lock_meta.get("files") or {}).items())
            ],
        },
        "binary_hashes": _binary_hashes(verdict_meta),
        "missing": missing,
    }
    body = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    return body, _sha256(body)


# -- finding.json ----------------------------------------------------------

def _four_state_events(store, finding_id: str) -> list[dict]:
    out = []
    for ev in store.events(finding_id):
        if ev["kind"] not in ("four_state", "loop_four_state"):
            continue
        m = _parse_meta(ev)
        out.append({
            "stage": ev["stage"] or "",
            "kind": ev["kind"],
            "message": ev["message"] or "",
            "phase": m.get("phase", ""),
            "four_state": (m.get("four_state")
                           or (m.get("state") if isinstance(m.get("state"),
                                                             str) else None)
                           or ""),
            "returncode": m.get("returncode"),
            "marker_present": (m.get("marker_present")
                               if isinstance(m.get("marker_present"), bool)
                               else None),
            "token_matches_pristine": (
                m.get("token_matches_pristine")
                if isinstance(m.get("token_matches_pristine"), bool) else None),
            "timestamp": ev["created_at"],
        })
    return out


def _build_finding_json(store, finding, artifacts, manifest_obj) -> bytes:
    """Dump every dashboard-visible piece of the finding as one JSON."""
    spec = json.loads(artifacts["spec"]["content"] or "{}")
    lock_meta = json.loads(artifacts["reproducer_lock"]["content"] or "{}")

    events = []
    for ev in store.events(finding.id):
        m = _parse_meta(ev)
        events.append({
            "id": ev["id"],
            "stage": ev["stage"] or "",
            "kind": ev["kind"] or "",
            "status": ev["status"] or "",
            "message": ev["message"] or "",
            "created_at": ev["created_at"],
            "duration_s": ev["duration_s"],
            "actor": ev["actor"] if "actor" in ev.keys() else "",
            "meta": m,
        })

    artifact_rows = []
    for a in store.artifacts(finding.id):
        artifact_rows.append({
            "id": a["id"],
            "kind": a["kind"] or "",
            "stage": a["stage"] or "",
            "model": a["model"] or "",
            "bytes": len(_artifact_bytes(a)),
            "created_at": a["created_at"],
            "meta": _parse_meta(a),
        })

    body = {
        "finding": {
            "id": finding.id,
            "parent_finding_id": finding.parent_finding_id or None,
            "source": finding.source,
            "source_ref": finding.source_ref,
            "repo_url": finding.repo_url,
            "cwe": finding.cwe,
            "title": finding.title,
            "description": finding.description,
            "stage": finding.stage,
            "state": finding.state,
            "container_id": finding.container_id,
            "created_at": finding.created_at,
            "updated_at": finding.updated_at,
        },
        "spec": spec,
        "reproducer_lock": lock_meta,
        "process_log": events,
        "artifacts": artifact_rows,
        "four_state_readings": _four_state_events(store, finding.id),
        "hash_triples": manifest_obj["hash_triples"],
        "pod_events": manifest_obj["pod_events"],
        "wall_frozen": manifest_obj["wall_frozen"],
        "budget_lifetime": manifest_obj["cost"],
    }
    return json.dumps(body, indent=2, sort_keys=True,
                      default=str).encode("utf-8")


# -- documentation files ---------------------------------------------------

_README_TEMPLATE = """# PatchWing evidence bundle

**Finding:** {finding_id}
**Reference:** {reference}
**CWE:** {cwe}
**Chain proved:** {chain_proved}
**Container image:** {image}

## What this bundle is

A portable, offline-verifiable record of one PatchWing finding: the crash
trace, the patch that closes it, the reproducer that fires it, the container
image and commands used to run everything, and the model's full prompt +
response trail. Every claim in `evidence.md` is backed by a file in this
archive whose sha256 is listed in `hashes.txt`.

Reads-only against PatchWing's store — no re-run happened at bundle time.

## Prerequisites

- podman (or docker; substitute `docker` for `podman` throughout)
- The container image referenced above (pulled on demand by the shell
  scripts, or you can pull it yourself: `podman pull {image}`)

## Verify it yourself in 60 seconds

```
# 1. Fire the pristine reproducer inside the container — should CRASH (red).
podman run --rm -it {image} sh -c 'arvo run'

# 2. Apply the patch and rebuild.
bash apply.sh <your_repo_checkout>
podman run --rm -v <your_repo_checkout>:/src -w /src {image} sh -c 'arvo compile'

# 3. Fire the reproducer again — should be GREEN (exit 0, no sanitizer marker).
bash verify.sh <your_container_or_checkout>

# 4. Roll back and confirm it goes red again.
bash rollback.sh <your_repo_checkout>
```

## File map

| Path | What it contains | What it proves |
|---|---|---|
| `evidence.md` | Human-readable PatchWing writeup | The story, in prose |
| `manifest.json` | Machine-readable provenance | Counts, hashes, seats, chain proof |
| `finding.json` | Full dashboard-parity dump | Every event, artifact, and reading |
| `patch.diff` | Unified diff (git-apply-ready) | The fix, in standard format |
| `patch.searchreplace.json` | Native SEARCH/REPLACE blocks | The model's raw edit output |
| `reproducer/poc` | Reproducer input bytes | Byte-identical to what was frozen |
| `reproducer/run.sh` | One-line invocation | How to fire the reproducer |
| `process-log.jsonl` | Every stage event | Timeline of the run |
| `prompts/` | Every model prompt (system + user body) | What the model saw |
| `responses/` | Every raw model response | What the model returned, verbatim |
| `verdicts/` | Verdict artifacts | The container's rulings |
| `advisory/` | Advisory reviewer output | Independent second-opinion (or unavailability reason) |
| `artifacts/` | Every raw artifact row's bytes | Full archive of the store's records |
| `spend/` | Cost accounting (JSONL) | Every model call's token/USD spend |
| `traces/investigation.jsonl` | Per-turn investigation trace | Tool calls the model made |
| `container.txt` | Image ref + digest | Which image the run used |
| `hashes.txt` | sha256 of every other file | Bundle-level integrity |
| `apply.sh` / `verify.sh` / `rollback.sh` | Deterministic scripts | Reproduce the verification |
| `APPLY.md` / `ROLLBACK.md` | Human instructions | What the scripts do |
| `arvo-comparison.md` | Post-review commentary comparing our patch to the ARVO developer patch | **Commentary, not a verdict.** The reproducer already decided this finding; this is a side-by-side reading for context. |

## Honest limits

- **Reproducer green ≠ no regression.** The reproducer only tests the one
  input that was frozen. This bundle does NOT run the wider project test
  suite. Doing that is on you.
- **Advisory review is advisory.** The container's four-state classifier is
  the verdict; the advisory model's opinion is a second read, not authority.
- **Container digest not resolved.** `container.txt` names the image tag,
  not a content-addressed digest. If the upstream tag moves, later pulls may
  drift.

## Where to report issues

Open an issue at your PatchWing installation's repo. Include the
`manifest.json` `finding_id` and `patchwing_version`.
"""


_APPLY_TEMPLATE = """# Apply this patch to a dev checkout

`apply.sh` is the deterministic version; this file is what it does.

## Prerequisites

- Your project cloned at some path `TARGET`.
- The file `patch.diff` (unified diff, git-apply-ready).

## Apply

```
cd $TARGET
git apply /path/to/patch.diff
```

## Hash-safety

`apply.sh` sha256-checks the target file BEFORE applying against
`manifest.chain_proof.before_sha256`. On a mismatch it EXITS NON-ZERO and
does not apply. Silent success on a drifted target is a bug.

## After apply

Build and test with your project's native workflow. The PatchWing container
was verified — you own the equivalent verification in your own build:

- Build clean
- Reproducer stops firing
- Full project suite still passes
- No new sanitizer warnings

## Rollback

See `ROLLBACK.md` or `bash rollback.sh $TARGET`.

## Drift handling

If `apply.sh` reports a hash mismatch, the file has changed upstream since
this patch was generated. Options: (a) rebase the patch onto the new
revision manually, (b) find the commit range the drift covers and cherry-pick
carefully, (c) discard this bundle and re-run PatchWing against the new
base.
"""


_ROLLBACK_TEMPLATE = """# Roll back this patch

The exact reverse of APPLY.md.

## Rollback

```
cd $TARGET
git apply -R /path/to/patch.diff
```

## Hash-safety

`rollback.sh` sha256-checks the target file BEFORE reverting against
`manifest.chain_proof.after_sha256`. On a mismatch it EXITS NON-ZERO and
does not revert.

## Verify the rollback

After `rollback.sh`, rebuild and run the reproducer — it should be RED
again (sanitizer marker present, matching DEDUP_TOKEN). If it stays GREEN
after rollback, either the undo mechanism drifted or your test path never
exercised the patched code. In either case, treat this as evidence NOT
being conclusive and re-investigate.
"""


def _apply_sh(before_sha: str, after_sha: str, patched_file: str) -> str:
    return f"""#!/usr/bin/env bash
# Deterministic patch application with hash safety.
# Usage: apply.sh <target_repo_path>
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <target_repo_path>" >&2
    exit 2
fi
TARGET="$1"
FILE="{patched_file}"
EXPECTED_BEFORE="{before_sha}"

if [ ! -f "$TARGET/$FILE" ]; then
    echo "ERROR: $TARGET/$FILE does not exist" >&2
    exit 3
fi

ACTUAL=$(sha256sum "$TARGET/$FILE" | awk '{{print $1}}')
if [ "$ACTUAL" != "$EXPECTED_BEFORE" ]; then
    echo "ERROR: $FILE has drifted from the pre-patch state." >&2
    echo "  expected sha256: $EXPECTED_BEFORE" >&2
    echo "  actual   sha256: $ACTUAL" >&2
    echo "Refusing to apply — see APPLY.md 'Drift handling'." >&2
    exit 4
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$TARGET"
git apply "$HERE/patch.diff"

AFTER=$(sha256sum "$FILE" | awk '{{print $1}}')
EXPECTED_AFTER="{after_sha}"
if [ "$AFTER" != "$EXPECTED_AFTER" ]; then
    echo "ERROR: post-apply hash mismatch." >&2
    echo "  expected: $EXPECTED_AFTER" >&2
    echo "  actual:   $AFTER" >&2
    echo "The patch applied but the resulting file differs from the recorded" >&2
    echo "chain_proof.after_sha256. Rolling back for safety." >&2
    git apply -R "$HERE/patch.diff" || true
    exit 5
fi
echo "OK: applied cleanly; $FILE now at $AFTER"
"""


def _rollback_sh(before_sha: str, after_sha: str, patched_file: str) -> str:
    return f"""#!/usr/bin/env bash
# Deterministic patch rollback with hash safety.
# Usage: rollback.sh <target_repo_path>
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <target_repo_path>" >&2
    exit 2
fi
TARGET="$1"
FILE="{patched_file}"
EXPECTED_BEFORE_REVERT="{after_sha}"

ACTUAL=$(sha256sum "$TARGET/$FILE" | awk '{{print $1}}')
if [ "$ACTUAL" != "$EXPECTED_BEFORE_REVERT" ]; then
    echo "ERROR: $FILE is not in the post-patch state; refusing to revert." >&2
    echo "  expected sha256 (post-patch): $EXPECTED_BEFORE_REVERT" >&2
    echo "  actual   sha256:              $ACTUAL" >&2
    exit 4
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$TARGET"
git apply -R "$HERE/patch.diff"

AFTER=$(sha256sum "$FILE" | awk '{{print $1}}')
EXPECTED_AFTER_REVERT="{before_sha}"
if [ "$AFTER" != "$EXPECTED_AFTER_REVERT" ]; then
    echo "ERROR: post-revert hash mismatch." >&2
    echo "  expected: $EXPECTED_AFTER_REVERT" >&2
    echo "  actual:   $AFTER" >&2
    exit 5
fi
echo "OK: reverted; $FILE now at $AFTER"
"""


def _verify_sh(image: str, repro_cmd: str, spec: dict | None = None) -> str:
    """Kind-aware detector.
    sanitizer -> historical ASan/MSan/UBSan/TSan grep, unchanged.
    http -> derive the RED pattern from spec.http.evidence_rules at
    bundle-generation time (name+pattern read from the finding record,
    never a literal). Keeps the shipped grader as one source of truth
    with states._classify_http.
    Fixes false-GREEN on http-shape findings — a verify.sh that can
    only emit GREEN is the same silent-green failure the wall module
    exists to prevent, one layer down."""
    import re as _re
    kind = "sanitizer"
    if spec:
        k = spec.get("reproducer_kind", "sanitizer")
        if k in ("sanitizer", "http"):
            kind = k

    if kind == "http":
        http_block = (spec or {}).get("http") or {}
        rules = http_block.get("evidence_rules") or []
        pieces = []
        rule_summary = []
        for r in rules:
            n = str(r.get("name", ""))
            p = str(r.get("pattern", ""))
            rk = str(r.get("kind", ""))
            rule_summary.append(f"{rk}:{n}={p!r}")
            if rk == "side_channel_flag":
                en, ep = _re.escape(n), _re.escape(p)
                pieces.append(f'"{en}"[[:space:]]*:[[:space:]]*"{ep}"')
                pieces.append(f'(^|\\n){en}[[:space:]]*:[[:space:]]*{ep}(\\n|$)')
            elif rk in ("side_channel_regex", "response_body_regex",
                        "response_header_regex"):
                pieces.append(p)
        combined = "|".join(f"({piece})" for piece in pieces) if pieces else ""
        rules_comment = " | ".join(rule_summary) if rule_summary else "(no rules)"
        detector = f'''
# HTTP-shape detector -- derived from spec.http.evidence_rules
# rules: {rules_comment}
RED_PATTERN={json.dumps(combined)}
if [ -z "$RED_PATTERN" ]; then
    echo "VERDICT: HARNESS_FAULT (no evidence rules declared in spec)" >&2
    exit 3
fi
if echo "$OUT" | grep -qE "$RED_PATTERN"; then
    echo "VERDICT: RED (http evidence rule matched)" >&2
    exit 1
fi
echo "VERDICT: GREEN (no http evidence rule matched)"'''
    else:
        detector = '''
if echo "$OUT" | grep -qE '(ERROR|SUMMARY): (Address|Memory|UndefinedBehavior|Thread)Sanitizer'; then
    echo "VERDICT: RED (sanitizer marker present)" >&2
    exit 1
fi
echo "VERDICT: GREEN (no sanitizer marker in reproducer output)"'''

    return f"""#!/usr/bin/env bash
# Run the reproducer inside the container. Exit non-zero if it fires (red).
# Detector kind: {kind}
# Usage: verify.sh [container_id_or_image]
set -euo pipefail
IMAGE="${{1:-{image}}}"

OUT=$(podman run --rm "$IMAGE" sh -c {json.dumps(repro_cmd)} 2>&1 || true)
echo "$OUT"
{detector}
"""


# -- assembler -------------------------------------------------------------

def _ordinal(n: int, width: int = 4) -> str:
    return f"{n:0{width}d}"


def _ext_for_kind(kind: str, sample_bytes: bytes) -> str:
    """Pick a filename extension for raw artifacts. Text-ish → .txt, JSON-ish
    → .json, everything else → .bin. Decision is bytes-shape based, not
    trusting the kind label."""
    if not sample_bytes:
        return "txt"
    head = sample_bytes[:256]
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        return "bin"
    stripped = head.strip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return "json"
    return "txt"


def _auto_populate_reproducer_input(store, finding_id: str, image: str,
                                     spec: dict) -> bool:
    """If the finding has no reproducer_input artifact yet, try to
    generate one from the committed image. Returns True if a fresh
    artifact was inserted.

    Bundle assembly requires reproducer_input (the payload bytes). For
    ARVO-style targets the payload is a static file (e.g. /tmp/poc)
    committed to the image; for HTTP-style targets it may be generated
    at runtime (e.g. our decompress finding uses make_exploit.js to
    build /tmp/exploit.zip on each reproduce). Both shapes are handled
    here so bundle.assemble doesn't crash on findings whose runtime
    payload wasn't pre-inserted.

    Resolution order for the payload path:
      1. spec.reproducer.payload_path (operator declares explicitly)
      2. spec.http.reproducer_input_path (http-shape convention)
      3. spec.reproducer.files first entry ending in .zip / .bin /
         .payload (heuristic — least trusted, so logged)
      4. /tmp/exploit.zip fallback (works for our zip-slip templates)

    If spec.reproducer.generate_cmd is present, run it inside the pod
    before reading the payload path — handles the runtime-generated
    case (make_exploit.js et al)."""
    import base64, subprocess, time, secrets
    # Skip if artifact already exists.
    for row in store.artifacts(finding_id, "reproducer_input"):
        return False

    if not image or image == "unknown":
        return False

    reproducer = (spec.get("reproducer") or {})
    http_block = (spec.get("http") or {})

    # HTTP-shape reproducers: if the spec is HTTP and no payload_path is
    # declared, synthesize reproducer_input as the request line + headers
    # (no need to spin a container). The URL IS the input — that's the
    # "payload" for HTTP GET vulnerabilities. Applies whenever spec has
    # an http block AND no payload_path override.
    kind = (spec.get("reproducer_kind") or "").strip()
    if kind == "http" and http_block and not reproducer.get("payload_path"):
        method = str(http_block.get("method") or "GET").upper()
        endpoint = str(http_block.get("endpoint_path_norm") or "/")
        request_bytes = (
            method + " " + endpoint + " HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n\r\n"
        ).encode("utf-8")
        b64 = base64.b64encode(request_bytes).decode("ascii")
        new_id = "httpinput" + secrets.token_hex(6)
        meta = {"encoding": "base64",
                "source": "bundle-auto-http-request-line",
                "filename": "http_request.txt",
                "method": method,
                "endpoint_path": endpoint,
                "bytes": len(request_bytes),
                "note": ("HTTP-shape reproducer has no request body — this is "
                         "the request line + Host header, documenting what the "
                         "reproducer sends.")}
        store.conn.execute(
            "INSERT INTO artifacts(id, finding_id, kind, stage, content, "
            "base_commit, meta, created_at, model) VALUES (?,?,?,?,?,?,?,?,?)",
            (new_id, finding_id, "reproducer_input", "package",
             b64, "", json.dumps(meta), time.time(), ""))
        store.conn.commit()
        return True

    payload_path = (reproducer.get("payload_path")
                    or http_block.get("reproducer_input_path"))
    if not payload_path:
        for f in reproducer.get("files") or []:
            fs = str(f).lower()
            if fs.endswith(".zip") or fs.endswith(".bin") or fs.endswith(".payload"):
                payload_path = f
                break
    if not payload_path:
        payload_path = "/tmp/exploit.zip"  # convention fallback

    generate_cmd = (reproducer.get("generate_cmd") or "").strip()

    # Spin a short-lived container to extract the payload.
    cid = "pw-bundle-extract-" + secrets.token_hex(4)
    inserted = False
    try:
        img_ref = image
        try:
            subprocess.run(["podman", "run", "-d", "--name", cid,
                             "--network=none",
                             img_ref, "sleep", "30"],
                            check=True, capture_output=True, timeout=15)
        except subprocess.CalledProcessError:
            img_ref = f"localhost/{image}" if not image.startswith("localhost/") else image
            subprocess.run(["podman", "run", "-d", "--name", cid,
                             "--network=none",
                             img_ref, "sleep", "30"],
                            check=True, capture_output=True, timeout=15)

        if generate_cmd:
            subprocess.run(["podman", "exec", cid, "bash", "-c", generate_cmd],
                            check=False, capture_output=True, timeout=60)

        out = subprocess.run(["podman", "exec", cid, "cat", payload_path],
                              capture_output=True, timeout=30)
        if out.returncode == 0 and out.stdout:
            payload = out.stdout
            b64 = base64.b64encode(payload).decode("ascii")
            new_id = "auto" + secrets.token_hex(6)
            meta = {"encoding": "base64",
                    "source": "bundle-auto-populated-from-image",
                    "filename": payload_path.rsplit("/", 1)[-1],
                    "payload_path": payload_path,
                    "generate_cmd": generate_cmd,
                    "bytes": len(payload)}
            store.conn.execute(
                "INSERT INTO artifacts(id, finding_id, kind, stage, content, "
                "base_commit, meta, created_at, model) VALUES (?,?,?,?,?,?,?,?,?)",
                (new_id, finding_id, "reproducer_input", "package",
                 b64, "", json.dumps(meta), time.time(), ""))
            store.conn.commit()
            inserted = True
    finally:
        # SIGTERM waits 10s then SIGKILL, so timeout must exceed that.
        # Also shielded: cleanup failures must not undo an insert or abort
        # bundle assembly.
        try:
            subprocess.run(["podman", "rm", "-f", cid],
                            capture_output=True, timeout=30)
        except (subprocess.TimeoutExpired, Exception):
            pass
    return inserted


def assemble(store, finding_id: str) -> BundleResult:
    finding = store.get(finding_id)
    if finding is None:
        raise BundleAssemblyError(["finding_row"], finding_id)

    # Auto-populate reproducer_input from the committed image if the
    # finding never persisted one (common for HTTP-shape whose payload
    # is generated at runtime). Best-effort: silently no-ops if the
    # image or spec doesn't give us enough hints; the required-check
    # below will still raise BundleAssemblyError with the specific
    # missing kind if auto-populate couldn't help.
    try:
        _prov_spec = store.latest_artifact(finding_id, "spec")
        if _prov_spec is not None:
            _spec_for_autopop = json.loads(_prov_spec["content"] or "{}")
            _img = str((_spec_for_autopop.get("target") or {}).get("image", "")).strip()
            _auto_populate_reproducer_input(store, finding_id, _img, _spec_for_autopop)
    except Exception as _e:
        pass  # non-fatal; required-check below is the real gate

    artifacts: dict = {}
    missing_kinds: list[str] = []
    for kind in REQUIRED_ARTIFACT_KINDS:
        art = store.latest_artifact(finding_id, kind)
        if art is None:
            missing_kinds.append(kind)
        else:
            artifacts[kind] = art
    if missing_kinds:
        raise BundleAssemblyError(missing_kinds, finding_id)

    spec = json.loads(artifacts["spec"]["content"] or "{}")
    cmds = spec.get("commands") or {}
    target = spec.get("target") or {}
    patch_meta = _parse_meta(artifacts["patch"])

    # Non-fatal missing items — recorded in manifest.missing[] but the bundle
    # still assembles. These are gaps in what the store has, not integrity
    # failures.
    missing: list[dict] = []
    all_response_arts = list(store.artifacts(finding_id, "response"))
    all_prompt_arts = list(store.artifacts(finding_id, "prompt"))
    if not all_response_arts:
        missing.append({
            "kind": "response",
            "reason": ("pre-persistence run, raw response body not captured "
                       "at call time. Only meta (confidence, byte counts) "
                       "is available; see process-log.jsonl 'response_received' events."),
        })
    if not patch_meta.get("edits_raw"):
        missing.append({
            "kind": "patch.edits_raw",
            "reason": ("pre-persistence run, raw SEARCH/REPLACE blocks not "
                       "captured. Only the parsed edit_blocks count survives; "
                       "patch.diff carries the applied result in unified form."),
        })

    # Build manifest (deterministic content)
    manifest_bytes, manifest_sha = _build_manifest(
        store, finding, artifacts, missing)
    manifest_obj = json.loads(manifest_bytes)
    short_sha = manifest_sha[:8]
    finding_json_bytes = _build_finding_json(
        store, finding, artifacts, manifest_obj)

    # -- assemble every archive file into a dict, sorted at write time ---
    files: dict[str, bytes] = {}

    files["evidence.md"] = _artifact_bytes(artifacts["evidence"])
    files["manifest.json"] = manifest_bytes
    files["finding.json"] = finding_json_bytes
    files["patch.diff"] = _artifact_bytes(artifacts["patch_diff"])
    files["patch.searchreplace.json"] = json.dumps({
        "file": patch_meta.get("file", ""),
        "edits": patch_meta.get("edits_raw", ""),  # the raw model output
        "analysis": patch_meta.get("analysis", ""),
        "confidence": patch_meta.get("confidence", ""),
        "edit_blocks_applied": patch_meta.get("edit_blocks", 0),
        "note": (""
                 if patch_meta.get("edits_raw")
                 else "edits field empty — pre-persistence finding; "
                      "see manifest.missing[]."),
    }, indent=2, sort_keys=True).encode("utf-8")

    files["reproducer/poc"] = _artifact_bytes(artifacts["reproducer_input"])
    files["reproducer/run.sh"] = (
        (cmds.get("reproduce") or "arvo run").strip() + "\n"
    ).encode("utf-8")
    files["container.txt"] = (
        f"image: {str(target.get('image', '')).strip()}\n"
        f"digest: unknown\n"
    ).encode("utf-8")

    # process-log.jsonl — every event
    log_lines = []
    for ev in store.events(finding_id):
        log_lines.append(json.dumps({
            "id": ev["id"],
            "created_at": ev["created_at"],
            "stage": ev["stage"] or "",
            "kind": ev["kind"] or "",
            "status": ev["status"] or "",
            "message": ev["message"] or "",
            "duration_s": ev["duration_s"],
            "meta": _parse_meta(ev),
        }, sort_keys=True, default=str))
    files["process-log.jsonl"] = ("\n".join(log_lines) + ("\n" if log_lines else "")).encode("utf-8")

    # prompts/
    for i, art in enumerate(all_prompt_arts, 1):
        m = _parse_meta(art)
        seat = m.get("seat", "unknown")
        model_short = _model_short(m.get("model", art["model"] or ""))
        name = f"prompts/{_ordinal(i)}-{seat}-{model_short}.txt"
        body = (
            f"# seat: {seat}\n"
            f"# model: {m.get('model', art['model'] or '')}\n"
            f"# endpoint: {m.get('endpoint', '')}\n"
            f"# created_at: {art['created_at']}\n"
            f"# primary_file: {m.get('primary_file', '')}\n"
            f"# view: {m.get('view', '')}\n"
            f"# user_message_bytes: {m.get('user_message_bytes', '')}\n"
            f"# ------------------------------\n"
            f"# SYSTEM MESSAGE\n"
            f"# ------------------------------\n"
            f"{m.get('system_message', '')}\n"
            f"# ------------------------------\n"
            f"# USER MESSAGE\n"
            f"# ------------------------------\n"
        ).encode("utf-8") + _artifact_bytes(art)
        files[name] = body

    # responses/
    for i, art in enumerate(all_response_arts, 1):
        m = _parse_meta(art)
        seat = m.get("seat", "unknown")
        model_short = _model_short(m.get("model", art["model"] or ""))
        name = f"responses/{_ordinal(i)}-{seat}-{model_short}.txt"
        body = (
            f"# seat: {seat}\n"
            f"# model: {m.get('model', art['model'] or '')}\n"
            f"# endpoint: {m.get('endpoint', '')}\n"
            f"# created_at: {art['created_at']}\n"
            f"# attempt: {m.get('attempt', '')}\n"
            f"# ------------------------------\n"
            f"# RAW RESPONSE BODY\n"
            f"# ------------------------------\n"
        ).encode("utf-8") + _artifact_bytes(art)
        files[name] = body

    # verdicts/
    for i, art in enumerate(store.artifacts(finding_id, "verdict"), 1):
        m = _parse_meta(art)
        seat = art["stage"] or "verify"
        name = f"verdicts/{_ordinal(i)}-{seat}.json"
        files[name] = json.dumps({
            "id": art["id"],
            "stage": art["stage"] or "",
            "model": art["model"] or "",
            "created_at": art["created_at"],
            "meta": m,
            "content": (art["content"] or ""),
        }, indent=2, sort_keys=True, default=str).encode("utf-8")

    # advisory/
    for i, art in enumerate(store.artifacts(finding_id, "review_advisory"), 1):
        m = _parse_meta(art)
        if m.get("available") is False:
            name = f"advisory/{_ordinal(i)}-unavailable.txt"
            files[name] = (
                f"advisory review unavailable\n"
                f"reason: {m.get('error', '(unspecified)')}\n"
                f"seat model: {m.get('reviewer_config', {}).get('model', '')}\n"
                f"seat endpoint: {m.get('reviewer_config', {}).get('endpoint', '')}\n"
                f"created_at: {art['created_at']}\n"
            ).encode("utf-8")
        else:
            seat = "verify_advisory"
            name = f"advisory/{_ordinal(i)}-{seat}.json"
            files[name] = json.dumps({
                "id": art["id"],
                "seat": seat,
                "model": art["model"] or "",
                "created_at": art["created_at"],
                "meta": m,
                "content": (art["content"] or ""),
            }, indent=2, sort_keys=True, default=str).encode("utf-8")

    # artifacts/ — every raw artifact row (including the ones already surfaced
    # elsewhere; this is the complete record)
    for i, art in enumerate(store.artifacts(finding_id), 1):
        kind = art["kind"] or "unknown"
        raw = _artifact_bytes(art)
        ext = _ext_for_kind(kind, raw)
        name = f"artifacts/{kind}-{_ordinal(i)}.{ext}"
        files[name] = raw

    # spend/
    def _spend_rows(k: str) -> bytes:
        lines = []
        for art in store.artifacts(finding_id, k):
            lines.append(json.dumps({
                "id": art["id"],
                "stage": art["stage"] or "",
                "model": art["model"] or "",
                "created_at": art["created_at"],
                "meta": _parse_meta(art),
            }, sort_keys=True, default=str))
        return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    files["spend/spend.jsonl"] = _spend_rows("spend")
    files["spend/spend_prior.jsonl"] = _spend_rows("spend_prior")

    # traces/investigation.jsonl — per-turn view of the investigation loop
    inv_lines: list[str] = []
    turns_by_number: dict[int, dict] = {}
    for ev in store.events(finding_id):
        kind = ev["kind"] or ""
        if not (kind.startswith("investigation_") or kind.startswith("loop_")):
            continue
        m = _parse_meta(ev)
        turn = m.get("turn")
        if turn is None:
            continue
        t = turns_by_number.setdefault(int(turn), {
            "turn": int(turn),
            "convo_bytes": None,
            "convo_messages": None,
            "remaining_usd": None,
            "spent_usd": None,
            "repro_status": None,
            "tool_calls": [],
            "duplicates": [],
            "patch_returned": False,
            "chain_proved": False,
        })
        if kind == "investigation_turn":
            t["convo_bytes"] = m.get("convo_bytes")
            t["convo_messages"] = m.get("convo_messages")
            t["remaining_usd"] = m.get("remaining_usd")
            t["spent_usd"] = m.get("spent_usd")
            t["repro_status"] = m.get("repro_status")
        elif kind == "investigation_tool_call":
            t["tool_calls"].append({
                "tool": m.get("tool", ""),
                "args": m.get("args", {}),
                "result_bytes": None,  # filled by matching tool_result later
            })
        elif kind == "investigation_tool_result":
            for c in reversed(t["tool_calls"]):
                if c.get("tool") == m.get("tool") and c.get("result_bytes") is None:
                    c["result_bytes"] = m.get("output_bytes")
                    if m.get("error"):
                        c["error"] = m.get("error")
                    break
        elif kind == "investigation_duplicate_call":
            t["duplicates"].append({
                "tool": m.get("tool", ""),
                "prior_turn": m.get("prior_turn"),
            })
        elif kind == "investigation_patch_returned":
            t["patch_returned"] = True
            t["edits_bytes"] = m.get("edits_bytes")
            t["analysis_bytes"] = m.get("analysis_bytes")
            t["confidence"] = m.get("confidence")
        elif kind == "investigation_chain_proved":
            t["chain_proved"] = True
            if "child_finding_id" in m:
                t["child_finding_id"] = m["child_finding_id"]

    for turn in sorted(turns_by_number):
        inv_lines.append(json.dumps(turns_by_number[turn],
                                    sort_keys=True, default=str))
    files["traces/investigation.jsonl"] = (
        "\n".join(inv_lines) + ("\n" if inv_lines else "")
    ).encode("utf-8")

    # ARVO post-review commentary. Bundle always includes the file; if no
    # arvo_comparison artifact exists, the file states that honestly and
    # manifest.arvo_comparison.present stays False. Never fabricates prose.
    arvo_art_here = store.latest_artifact(finding.id, "arvo_comparison")
    if arvo_art_here is not None:
        files["arvo-comparison.md"] = _artifact_bytes(arvo_art_here)
    else:
        files["arvo-comparison.md"] = (
            "ARVO developer patch not available for this finding; "
            "no comparison generated.\n"
        ).encode("utf-8")

    # Docs + scripts
    files["README.md"] = _README_TEMPLATE.format(
        finding_id=finding.id,
        reference=finding.source_ref or "(none)",
        cwe=finding.cwe or "unspecified",
        chain_proved=str(manifest_obj["chain_proof"]["chain_proved"]),
        image=str(target.get("image", "")).strip() or "unknown",
    ).encode("utf-8")
    files["APPLY.md"] = _APPLY_TEMPLATE.encode("utf-8")
    files["ROLLBACK.md"] = _ROLLBACK_TEMPLATE.encode("utf-8")

    triple = manifest_obj["chain_proof"]
    patched_file = (patch_meta.get("file") or "").strip()
    files["apply.sh"] = _apply_sh(
        triple["before_sha256"], triple["after_sha256"], patched_file
    ).encode("utf-8")
    files["rollback.sh"] = _rollback_sh(
        triple["before_sha256"], triple["after_sha256"], patched_file
    ).encode("utf-8")
    files["verify.sh"] = _verify_sh(
        str(target.get("image", "")).strip() or "unknown",
        (cmds.get("reproduce") or "arvo run").strip(),
        spec=spec,
    ).encode("utf-8")

    # hashes.txt — sha256 of every OTHER file
    hash_lines = [f"{_sha256(files[p])}  {p}" for p in sorted(files)]
    files["hashes.txt"] = ("\n".join(hash_lines) + "\n").encode("utf-8")

    # Deterministic tar → gzip
    mtime = int(finding.created_at)
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        for path in sorted(files):
            data = files[path]
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            info.mtime = mtime
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            # apply/rollback/verify need execute bit
            info.mode = 0o755 if path.endswith(".sh") else 0o644
            tar.addfile(info, io.BytesIO(data))
    raw_tar = tar_buf.getvalue()

    gz_buf = io.BytesIO()
    with gzip.GzipFile(
        fileobj=gz_buf, mode="wb", mtime=0, compresslevel=6, filename=""
    ) as gz:
        gz.write(raw_tar)
    archive = gz_buf.getvalue()

    return BundleResult(
        finding_id=finding.id,
        filename=f"patchwing-{finding.id}-{short_sha}.tar.gz",
        short_sha=short_sha,
        manifest_sha256=manifest_sha,
        bytes=archive,
    )
