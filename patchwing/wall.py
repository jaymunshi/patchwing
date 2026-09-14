"""The reproducer wall — the mechanism that makes a PatchWing verdict trustworthy.

Trust does not live in which model wrote the fix. The fix is never trusted; it is
*tested*. A patch is accepted only when the frozen reproducer failed before it,
passes after it, and the project's own suite stays green. A container decides that,
not a model.

That argument only holds if the reproducer is the *same artifact* before and after.
A fix-writer that can edit the test proving the bug can make any patch look correct —
this is why weak tests passing bad patches is a known failure of the field, not a
hypothetical. So the wall is enforced three ways, in increasing order of strength:

  1. **Sequence** — the manifest is frozen during `reproduce`, before a patch exists.
  2. **Permission** — frozen files are made read-only in the sandbox.
  3. **Assertion** — hashes are re-checked after the patch is applied. A changed
     hash voids the run. This is the one that actually holds, because it does not
     depend on the earlier two having worked.

The wall is *temporal, not identity-based*: the same model may write both the
reproducer and the fix, provided the reproducer was frozen first and never revised.
Nothing here inspects which model did what.

The manifest is item 9 of the evidence package. A third party re-running the
container can recompute every hash and confirm the reproducer they are reading is
the reproducer that ran.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat

# Files that must not change across the patch. Two categories, both protected:
#   reproducer — proves the bug was real
#   suite      — proves nothing else broke
_TEST_PAT = re.compile(
    r"(^|/)(tests?|testing)/"
    r"|(^|/)test_[^/]*$"
    r"|_test\.[A-Za-z0-9]+$"
    r"|(^|/)conftest\.py$"
    r"|(^|/)tests\.py$"
)

_CODE_EXT = re.compile(r"\.(py|js|ts|go|rb|java|c|cc|cpp|h|rs|php|sh)$")

# Directories never worth walking when collecting the suite.
_SKIP_DIRS = {".git", ".hg", "__pycache__", "node_modules", ".venv", "venv",
              ".tox", ".mypy_cache", ".pytest_cache", "build", "dist"}

MAX_FILES = 4000  # a manifest larger than this means the target dir is wrong


class WallError(Exception):
    """Raised when the wall cannot be established at all."""


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def reproducer_files(spec: dict, target_dir: str) -> list[str]:
    """Which files constitute the reproducer. DECLARED ONLY — never inferred.

    This used to infer the reproducer from path-looking tokens in the reproduce
    command. On ARVO the command is `arvo run`, which contains no path, so the
    inference found nothing, froze nothing, and REPORTED SUCCESS — the wall
    protecting the machine artifact protected the machine artifact not at all.

    A check that cannot fail is not a check. Inference is removed rather than
    improved: there is no heuristic that fails loudly, and a wall that guesses is
    a wall that can be silently empty.
    """
    return [f for f in ((spec.get("reproducer") or {}).get("files") or []) if f]


def suite_files(spec: dict, target_dir: str) -> list[str]:
    """Files that must not change because they prove nothing else broke.

    Declared, like the reproducer. An ABSENT [suite] table and an EMPTY one mean
    different things and are treated differently: absent falls back to scanning
    for test files (the historical behaviour, correct for a checked-out tree),
    while `files = []` is an explicit statement that this corpus has no separate
    regression suite. ARVO is the latter — its targets are fuzz harnesses, not
    projects with test suites — and stating that explicitly is what stops the
    scan from sweeping 1,483 SOURCE files into the frozen set, which would then
    make the very file the fix-writer must edit immutable.
    """
    suite = spec.get("suite")
    if isinstance(suite, dict) and "files" in suite:
        return [f for f in (suite.get("files") or []) if f]

    out = []
    for root, dirs, names in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), target_dir).replace("\\", "/")
            if _TEST_PAT.search(rel) and _CODE_EXT.search(rel):
                out.append(rel)
        if len(out) > MAX_FILES:
            raise WallError(
                f"more than {MAX_FILES} suite files under {target_dir!r} — the "
                f"target directory looks wrong, or this corpus needs an explicit "
                f"[suite] files = [] declaration")
    return out


def protected_files(spec: dict, target_dir: str) -> dict[str, str]:
    """Every file the fix-writer must not touch, mapped to why."""
    out: dict[str, str] = {}
    for rel in reproducer_files(spec, target_dir):
        out[rel.replace("\\", "/")] = "reproducer"
    for rel in suite_files(spec, target_dir):
        out.setdefault(rel.replace("\\", "/"), "suite")
    return out


def freeze(spec: dict, target_dir: str) -> dict:
    """Hash every protected file. Called during `reproduce`, before a patch exists."""
    prot = protected_files(spec, target_dir)
    entries = {}
    for rel, reason in sorted(prot.items()):
        full = os.path.join(target_dir, rel)
        try:
            entries[rel] = {"sha256": _sha256(full), "reason": reason,
                            "bytes": os.path.getsize(full)}
        except OSError as e:
            raise WallError(f"cannot hash protected file {rel}: {e}") from e
    return {
        "algorithm": "sha256",
        "n_files": len(entries),
        "n_reproducer": sum(1 for v in entries.values() if v["reason"] == "reproducer"),
        "files": entries,
    }


def harden(target_dir: str, manifest: dict) -> int:
    """Make protected files read-only. Defence in depth, not the guarantee —
    a process running as the owner can still chmod them back, which is exactly
    why `check` exists."""
    n = 0
    for rel in manifest.get("files", {}):
        full = os.path.join(target_dir, rel)
        try:
            mode = os.stat(full).st_mode
            os.chmod(full, mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            n += 1
        except OSError:
            pass
    return n




# Rev-1 + Rev-6: enforce that commands.reproduce runs a frozen file, no
# inline shell body. Exemption for ARVO shape (operator-declared reproducer
# + prebuilt image) requires TWO signals AND ingest-stage provenance.
#
# Two classes, matched DIFFERENTLY (the substring-for-everything version had a
# false-positive bug: any path containing "-c" — e.g. /pw/run-check.sh,
# /tmp/vite-cve.sh — was rejected as if it were a shell `-c` flag):
#   _META_CHARS  — real shell metacharacters. Substring match, because they
#                  are dangerous even embedded inside a token ("a&&b").
#   _META_FLAGS  — interpreter flags that smuggle inline code (`bash -c '...'`).
#                  EXACT-TOKEN match only — a flag is a whole argv element, so
#                  a path that merely contains the letters is not one.
_META_CHARS = (";", "&&", "||", "|", "`", "$(")
_META_FLAGS = ("-c", "-eval")
# Back-compat alias — nothing outside this module reads it, but keep the name.
_META_TOKENS = _META_CHARS + _META_FLAGS


def _has_metachar(tokens: list[str]) -> str:
    """Return the offending token or '' if clean.

    A token offends if it IS an inline-code flag (`-c`, `-eval`) by EXACT
    match, OR it CONTAINS a real shell metacharacter (';', '&&', '|',
    backtick, '$(') as a substring."""
    for t in tokens:
        if t in _META_FLAGS:            # exact — a flag is a whole argv element
            return t
        for m in _META_CHARS:           # substring — embedded metachars still bite
            if m in t:
                return t
    return ""


def _split_on_and(tokens: list[str]) -> list[list[str]]:
    """Split an argv token list on standalone '&&' tokens into segments.

    `shlex.split("cd /x && bash /y.sh")` yields '&&' as its own token, so a
    `cd <dir> && <cmd>` prefix is recognisable structurally. A '&&' embedded
    inside a single token ('a&&b', no surrounding spaces) is NOT split here —
    it stays inside its segment and is caught by _has_metachar's substring
    check. Returns at least one segment."""
    segs: list[list[str]] = [[]]
    for t in tokens:
        if t == "&&":
            segs.append([])
        else:
            segs[-1].append(t)
    return segs


def _is_cd_prefix(seg: list[str]) -> bool:
    """True iff a segment is exactly `cd <one-path>` with no metacharacters.

    This is the ONLY multi-segment form the shape check permits: a reproduce
    command may `cd` into the target dir before invoking the frozen file
    (`cd /opt/target && bash reproduce.sh`). The `cd` path is still run
    through _has_metachar so `cd $(evil)` is refused."""
    return (len(seg) == 2 and seg[0] == "cd" and not _has_metachar(seg))


def _spec_uses_arvo_compat(spec: dict) -> bool:
    """True iff this spec carries the prebuilt-runner shape the exemption is for.

    The signal is `target.prebuilt` — the marker real ARVO / OSS-Fuzz specs
    actually set (image baked upstream, reproducer invoked by a corpus runner
    like `arvo run` that legitimately does not name the frozen poc by path).
    The earlier form additionally required
    `reproducer.origin == "operator_target_toml"`, a string NO real ARVO spec
    on disk ever set — so the exemption never fired and `arvo run` was wrongly
    refused. `origin` is still ACCEPTED as an alternative signal for the
    operator-target-toml path, but `prebuilt` alone is sufficient.

    This does not weaken anti-forgery: the exemption only fires when
    `_validate_arvo_compat_provenance` also confirms the flag was set at the
    INGEST stage, so a later stage (provision) cannot set `prebuilt` to exempt
    itself. And it only waives the 'command names a frozen file' clause — the
    metacharacter check and the non-empty-frozen-set check still run."""
    origin = ((spec.get("reproducer") or {}).get("origin") or "").strip()
    prebuilt = bool((spec.get("target") or {}).get("prebuilt"))
    return prebuilt or origin == "operator_target_toml"


def _validate_arvo_compat_provenance(store, finding_id: str) -> bool:
    """Rev-6: bypass exemption requires that the origin/prebuilt fields
    were set at INGEST stage. Provision-stage specs are forbidden from
    setting them (normalize_spec rejects; this is the wall backstop).

    Returns True if the finding's earliest spec artifact set the bypass
    fields; False otherwise (bypass rejected, strict shape check runs)."""
    if store is None:
        return False
    try:
        rows = store.artifacts(finding_id, "spec")
    except Exception:
        return False
    if not rows:
        return False
    # Earliest first.
    for row in rows:
        stage = (row["stage"] if hasattr(row, "keys") and "stage" in row.keys()
                 else row.get("stage", ""))
        if stage != "ingest":
            continue
        try:
            import json
            s0 = json.loads(row["content"] or "{}")
        except Exception:
            continue
        if _spec_uses_arvo_compat(s0):
            return True
    return False


def _references_frozen(tokens: list[str], files: list[str]) -> bool:
    """True if any token invokes one of the frozen files.

    Tolerant of a relative basename left after a `cd <dir>` prefix — after
    `cd /opt/target` the command `bash reproduce.sh` invokes the frozen
    absolute path `/opt/target/reproduce.sh`, so a basename / path-suffix
    match counts. The load-bearing tamper guarantee is still the wall's
    post-patch hash re-check on the frozen absolute path; this is only the
    structural shape check."""
    for f in files:
        base = f.rsplit("/", 1)[-1]
        for t in tokens:
            if (t == f or t == base
                    or t.endswith("/" + base)
                    or f.endswith("/" + t)
                    or t.endswith(f)):
                return True
    return False


def validate_command_shape(spec: dict, store=None, finding_id: str = "") -> None:
    """Refuses to establish if commands.reproduce embeds executable body
    or does not reference a frozen file.

    Permitted shapes:
      <interpreter> <frozen-file> [args...]
      cd <dir> && <interpreter> <frozen-file> [args...]     (one or more cd's)
      <corpus runner>                                        (ARVO/prebuilt only)

    ARVO/prebuilt exemption waives ONLY the 'names a frozen file' clause and
    requires ingest-stage provenance (Rev-6). The metacharacter check and the
    non-empty-frozen-set check ALWAYS run, exemption or not."""
    import shlex
    cmd = str((spec.get("commands") or {}).get("reproduce") or "").strip()
    if not cmd:
        raise WallEstablishError(
            "spec.commands.reproduce is empty; nothing to freeze against.")
    try:
        tokens = shlex.split(cmd)
    except ValueError as e:
        raise WallEstablishError(
            f"commands.reproduce parse error: {e}. Reject: unbalanced quotes "
            f"or shell fragments cannot be safely frozen.")

    # A `cd <dir> &&` prefix is the ONLY multi-segment form allowed: a reproduce
    # command may change into the target directory before invoking the frozen
    # file. Every segment before the last must be exactly `cd <path>`; the last
    # segment is the effective command. Any other '&&' usage
    # (`bash a.sh && rm -rf`) is refused because the non-final segment is not a cd.
    segments = _split_on_and(tokens)
    for seg in segments[:-1]:
        if not _is_cd_prefix(seg):
            raise WallEstablishError(
                f"commands.reproduce chains commands with '&&' beyond a leading "
                f"`cd <dir>` prefix (offending segment: {' '.join(seg)!r}). Only "
                f"`cd <dir> && <interpreter> <frozen-file>` is permitted; move "
                f"any other logic into a file listed in reproducer.files.")
    effective = segments[-1]

    # Metacharacter check on every segment (the split removed only the standalone
    # '&&' tokens joining cd-prefixes; ';', '|', '$(', backtick, an embedded
    # '&&', and inline-code flags -c/-eval are all still caught here).
    for seg in segments:
        offender = _has_metachar(seg)
        if offender:
            raise WallEstablishError(
                f"commands.reproduce embeds executable body / metacharacter "
                f"({offender!r}). Move the logic to a file listed in "
                f"reproducer.files and invoke it as `<interpreter> <path>`.")

    files = [f for f in ((spec.get("reproducer") or {}).get("files") or []) if f]
    if not files:
        # Checked BEFORE the exemption so a prebuilt spec cannot waive it — an
        # empty frozen set is a silently-empty wall, the exact failure this
        # whole mechanism exists to prevent.
        raise WallEstablishError(
            "commands.reproduce declares no frozen file to invoke — "
            "reproducer.files is empty. Provision must materialize the "
            "reproducer to a file (see PROVISION_SYSTEM REPRODUCER CONTRACT).")

    # ARVO/prebuilt exemption: waive ONLY the 'names a frozen file' clause (a
    # corpus runner like `arvo run` invokes the frozen poc without naming its
    # path). Requires verified ingest-stage provenance so a later stage cannot
    # forge the flag to exempt itself.
    if (_spec_uses_arvo_compat(spec)
            and _validate_arvo_compat_provenance(store, finding_id)):
        return

    if not _references_frozen(effective, files):
        raise WallEstablishError(
            "commands.reproduce runs no file listed in reproducer.files "
            f"(command tokens: {effective!r}, frozen: {files!r}). A patch could "
            "rewrite the command undetected.")


class WallEstablishError(Exception):
    """Wall refuses to establish because the spec violates a hard contract."""


def check(target_dir: str, manifest: dict) -> list[dict]:
    """Re-hash after the patch. Any entry returned means the run is void."""
    violations = []
    for rel, ent in (manifest.get("files") or {}).items():
        full = os.path.join(target_dir, rel)
        if not os.path.isfile(full):
            violations.append({"file": rel, "reason": ent.get("reason"),
                               "problem": "deleted"})
            continue
        try:
            now = _sha256(full)
        except OSError as e:
            violations.append({"file": rel, "reason": ent.get("reason"),
                               "problem": f"unreadable: {e}"})
            continue
        if now != ent.get("sha256"):
            violations.append({
                "file": rel, "reason": ent.get("reason"), "problem": "modified",
                "expected": ent.get("sha256")[:16], "actual": now[:16],
            })
    return violations


def is_protected(rel: str, manifest: dict) -> str | None:
    """Why `rel` may not be patched, or None if it is fair game."""
    ent = (manifest.get("files") or {}).get(rel.replace("\\", "/"))
    return ent.get("reason") if ent else None


def summarize(manifest: dict) -> str:
    n = manifest.get("n_files", 0)
    r = manifest.get("n_reproducer", 0)
    return (f"{n} file(s) frozen under sha256 "
            f"({r} reproducer, {n - r} suite)")


# ---------------------------------------------------------------------------
# Containerised targets
#
# For an in-image target the protected files have NO host-side existence:
# /tmp/poc lives only inside the container, and it is outside the source root
# (/src/libxml2). So hashing runs through the sandbox rather than os.walk, and
# declared paths may be absolute.
# ---------------------------------------------------------------------------

def freeze_in_sandbox(sb, spec: dict) -> dict:
    """Hash the declared protected files INSIDE the container.

    Aborts if the reproducer set is empty. That is the whole lesson of the
    inference bug: a wall that can be silently empty reports success while
    protecting nothing, so an empty reproducer set is a hard failure and not a
    log line.
    """
    repro = reproducer_files(spec, "")
    if not repro:
        raise WallError(
            "no reproducer files declared. Add [reproducer] files = [...] to the "
            "target spec naming the artifact that proves the bug (for a fuzz "
            "target, the minimized testcase). The wall refuses to run without "
            "knowing what it is protecting — a wall that guesses can be silently "
            "empty, which is what happened when it inferred from the reproduce "
            "command.")

    suite = suite_files(spec, "") if isinstance(spec.get("suite"), dict) else []
    entries: dict[str, dict] = {}
    for rel, reason in ([(r, "reproducer") for r in repro]
                        + [(s2, "suite") for s2 in suite]):
        # sha256, not md5. The manifest is tamper evidence: a stranger who
        # computes the algorithm we NAME must get the value we PRINT. Labelling a
        # 32-hex md5 as "sha256" makes an honest verifier see a mismatch and read
        # it as tampering — a false tamper signal inside the tamper-evidence
        # artifact, which is the worst possible place for one.
        r = sb.run(f"sha256sum {rel} 2>/dev/null | cut -d' ' -f1; "
                   f"stat -c %s {rel} 2>/dev/null")
        parts = [x for x in (r.stdout or "").split() if x]
        if len(parts) < 2:
            raise WallError(
                f"declared protected file {rel!r} does not exist in the image. "
                f"The wall cannot protect a file it cannot hash.")
        if len(parts[0]) != 64:
            raise WallError(
                f"expected a 64-hex sha256 for {rel!r}, got {len(parts[0])} "
                f"chars — refusing to record a hash under the wrong algorithm")
        entries[rel] = {"sha256": parts[0], "reason": reason,
                        "bytes": int(parts[1]), "algorithm": "sha256"}
    return {
        "algorithm": "sha256",
        "n_files": len(entries),
        "n_reproducer": len(repro),
        "n_suite": len(suite),
        "suite_declared_empty": isinstance(spec.get("suite"), dict) and not suite,
        "files": entries,
        "in_image": True,
    }


def check_in_sandbox(sb, manifest: dict) -> list[dict]:
    """Re-hash inside the container after the patch."""
    violations = []
    for rel, ent in (manifest.get("files") or {}).items():
        r = sb.run(f"sha256sum {rel} 2>/dev/null | cut -d' ' -f1")
        now = (r.stdout or "").strip()
        if not now:
            violations.append({"file": rel, "reason": ent.get("reason"),
                               "problem": "missing or unreadable"})
        elif now != ent.get("sha256"):
            violations.append({"file": rel, "reason": ent.get("reason"),
                               "problem": "modified",
                               "expected": ent.get("sha256")[:16],
                               "actual": now[:16]})
    return violations




def check_verdict_config_drift(spec: dict, manifest: dict) -> None:
    """Rev-2: at verify entry, compare current spec's http slice against
    the frozen verdict_config in reproducer_lock. Raises WallEstablishError
    on any drift so a mid-run rules rewrite cannot flip the verdict."""
    lock_vc = manifest.get("verdict_config") or {}
    if not lock_vc or lock_vc.get("kind") != "http":
        return  # sanitizer kind or no verdict_config recorded — no-op
    from . import states as _states
    now_http = spec.get("http") or {}
    now_vc = _states.serialize_pristine_http(
        now_http,
        observed_status=int(lock_vc.get("status", 0) or 0))
    # Only fields _classify_http reads matter — compare canonical dict.
    fields_to_check = ("endpoint_path_norm", "method",
                        "expected_green_statuses",
                        "body_fingerprint_negative_list", "evidence_rules")
    diffs = []
    for k in fields_to_check:
        if lock_vc.get(k) != now_vc.get(k):
            diffs.append(k)
    if diffs:
        raise WallEstablishError(
            f"verdict_config drifted since establish: fields differ = {diffs}. "
            f"Reproducer_lock is authoritative; current spec's http slice "
            f"disagrees. Refusing verify to prevent silent verdict flip.")


def assert_patchable(rel: str, manifest: dict, root: str = "") -> None:
    """The file the fix-writer must edit MUST NOT be frozen.

    Asserted rather than assumed. If the frozen set and the patch target overlap,
    the patch either fails against a read-only file or trips the post-patch hash
    check and is voided as tampering — and both read as the model failing to fix
    the bug. A harness fault wearing the model's face.
    """
    cands = {rel, rel.lstrip("/")}
    if root:
        cands.add(f"{root.rstrip('/')}/{rel.lstrip('/')}")
    for c in cands:
        why = is_protected(c, manifest)
        if why:
            raise WallError(
                f"the patch target {rel!r} is inside the frozen set ({why}). "
                f"The frozen set and the patch target must be disjoint: the "
                f"fix-writer cannot edit a file the wall is protecting. Declare "
                f"the reproducer and suite precisely so source files are not "
                f"swept in.")
