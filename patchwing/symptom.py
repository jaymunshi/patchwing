"""Symptom-based localization — finding the bug without being told where it is.

PatchWing's existing localizer resolves the upstream fix commit and reads the
changed files off it. That works, and it is also the reason PatchWing can only
process vulnerabilities somebody has already fixed: no fix commit, no localization,
no pipeline. The entire "reported but unfixed" case has no code path.

This module is that path. It reasons the way a maintainer does — forward from the
symptom, not backward from the answer:

    stack trace     -> which file was executing when it broke      (strongest)
    revision range  -> which files changed when the bug appeared   (strong)
    advisory text   -> which component implements the named APIs   (weakest, but
                                                                    always present)

Nothing here reads the fix. Nothing here needs the fix to exist.

**Accuracy of this module is UNMEASURED.** Nothing here has been benchmarked.

There is a prior result that must not be attributed to this code: a standalone
advisory-only ranking experiment scored 68.4% top-1 on 19 CVEs against a 42.1%
string-matching baseline, and held at 68.4% when path tokens were masked out while
the baseline collapsed to 10.5% (random floor 4.4%). That established the general
point that advisory-to-file ranking is reasoning rather than filename matching — but
it ran on a **different, superseded implementation** with a different prompt,
advisory-only input, and no trace or revision handling. It is *prior implementation,
advisory-only input, superseded*, and it is not this module's score.

The two signals this module adds — stack traces and revision ranges — are strictly
better evidence than advisory prose in principle, but their contribution has never
been measured at all. ARVO supplies the traces that would let us measure it. Until
then, treat every number about this module as absent, not as inherited.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

# Stack-trace shapes worth parsing: (pattern, innermost_first).
#
# Frame ORDER is not consistent across formats and it decides which file we blame.
# Python prints outermost first, so the crash site is the LAST frame. ASan, Java and
# V8 print innermost first, so it is the FIRST. Getting this backwards blames the
# entry point instead of the vulnerable function, so every pattern declares its
# convention and parse_trace normalises to innermost-first.
_TRACE_PATTERNS = [
    # Python:  File "/app/x/y.py", line 42, in func      (outermost first)
    (re.compile(r'File "([^"]+)", line (\d+)'), False),
    # ASan / gdb:  #3 0x... in func /src/x/y.c:42:9      (innermost first)
    (re.compile(r'#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S+\s+([^\s:]+):(\d+)'), True),
    # Node / V8:  at func (/app/x/y.js:42:13)            (innermost first)
    (re.compile(r'\sat\s+.*?\(([^):]+):(\d+):\d+\)'), True),
    # Java:  at com.x.Y.method(Y.java:42)                (innermost first)
    (re.compile(r'\sat\s+[\w.$]+\(([\w$]+\.java):(\d+)\)'), True),
    # Go:  /app/x/y.go:42 +0x1c                          (innermost first)
    (re.compile(r'([^\s:]+\.go):(\d+)'), True),
    # generic  path/to/file.ext:42 — no ordering information, take as written
    (re.compile(r'\b([\w./\\-]+\.(?:py|c|cc|cpp|h|hpp|rs|rb|php|ts|js|go|java)):(\d+)\b'),
     True),
]

_CODE_EXT = re.compile(r"\.(py|js|ts|go|rb|java|c|cc|cpp|h|hpp|rs|php)$")
_TEST_PAT = re.compile(
    r"(^|/)(tests?|testing)/|(^|/)test_[^/]*$|_test\.[A-Za-z0-9]+$"
    r"|(^|/)conftest\.py$|(^|/)tests\.py$")
_SKIP_DIRS = {".git", ".hg", "__pycache__", "node_modules", ".venv", "venv",
              ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
              "vendor", "third_party", ".patchwing"}
# Frames inside the language runtime or installed dependencies are noise: the bug
# is almost never in the stdlib, and we cannot patch it there anyway.
_FOREIGN = re.compile(
    # interpreted-language dependency dirs
    r"(^|/)(site-packages|dist-packages|node_modules|vendor|third_party)/"
    r"|^/usr/|(^|/)lib/python\d"
    # system libraries — verified against a real MSan trace, where
    # /lib/x86_64-linux-gnu/libc.so.6 slipped past a /usr/-only pattern
    r"|(^|/)lib/[^/]*-linux-gnu/|\.so(\.\d+)*$"
    # sanitizer and fuzzer runtime: these are the INNERMOST frames of all, so
    # "take the innermost" without filtering blames the instrumentation itself
    r"|(^|/)compiler-rt/|(^|/)(libfuzzer|llvm)/|(^|/)msan_|(^|/)asan_"
    r"|FuzzerLoop\.cpp$|FuzzerDriver\.cpp$|FuzzerMain\.cpp$")

MAX_CANDIDATES = 1500


def parse_trace(text: str) -> list[tuple[str, int]]:
    """Extract (path, line) frames from a stack trace, **innermost first**.

    Innermost first means the crash site leads, which is what downstream ranking
    assumes. Formats that print outermost-first are reversed here so callers never
    have to care which language produced the trace.
    """
    if not text:
        return []
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for pat, innermost_first in _TRACE_PATTERNS:
        found = []
        for m in pat.finditer(text):
            path, line = m.group(1), int(m.group(2))
            if _FOREIGN.search(path):
                continue
            found.append((path, line))
        if not innermost_first:
            found.reverse()
        for key in found:
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def trace_files(text: str, target_dir: str) -> list[str]:
    """Frames from the trace that correspond to files in *this* project.

    A trace usually names absolute paths from wherever it ran; match by suffix so
    /src/foo/bar.c finds foo/bar.c in the checkout.
    """
    frames = parse_trace(text)
    if not frames:
        return []
    have = set(enumerate_candidates(target_dir, include_tests=True))
    hits: list[str] = []
    for path, _line in frames:
        norm = path.replace("\\", "/").lstrip("./")
        if norm in have and norm not in hits:
            hits.append(norm)
            continue
        for cand in have:
            if (norm.endswith("/" + cand) or cand.endswith("/" + norm)
                    or os.path.basename(cand) == os.path.basename(norm)):
                if cand not in hits:
                    hits.append(cand)
                break
    return hits


def enumerate_candidates(target_dir: str, include_tests: bool = False) -> list[str]:
    """Project source files a fix could plausibly land in."""
    out: list[str] = []
    for root, dirs, names in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), target_dir).replace(os.sep, "/")
            if not _CODE_EXT.search(rel):
                continue
            if not include_tests and _TEST_PAT.search(rel):
                continue
            out.append(rel)
            if len(out) > MAX_CANDIDATES * 2:
                break
    return sorted(out)


def narrow_by_revision(target_dir: str, good: str, bad: str) -> list[str]:
    """Files that changed between a known-good and known-bad revision.

    When a bug report carries a regression range this is the sharpest evidence
    available short of a stack trace: the bug was introduced by one of these.
    Returns [] when the range is unusable rather than raising — it is an optional
    signal, not a requirement.
    """
    if not (good and bad):
        return []
    try:
        p = subprocess.run(
            ["git", "-C", target_dir, "diff", "--name-only", f"{good}..{bad}"],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return []
    if p.returncode != 0:
        return []
    return [x.strip() for x in p.stdout.splitlines()
            if x.strip() and _CODE_EXT.search(x) and not _TEST_PAT.search(x)]


RANK_SYSTEM = """You are a security engineer triaging a vulnerability report against \
a codebase. Identify which file contains the vulnerable code that must be changed.

Reason from the symptom to the cause the way a maintainer would: the advisory names \
behaviour, APIs or functions; find the file that implements them. Where a stack trace \
or a regression range is supplied, weigh it above the prose — it is direct evidence \
of what was executing, while the prose is a description.

Some component names may appear as opaque placeholders. Do not rely on filename \
similarity alone; a file whose name merely resembles a word in the advisory is a weak \
candidate compared with one whose responsibility matches the described behaviour.

Reply ONLY with JSON:
  {"ranked": ["path1", ..., "path5"], "why": "one sentence for the top choice"}
Most likely first, exact paths from the candidate list."""


def _extract_ranked(txt: str) -> tuple[list[str], str]:
    m = re.search(r"\{.*\}", txt or "", re.S)
    if m:
        try:
            obj = json.loads(m.group(0))
            return (obj.get("ranked") or []), (obj.get("why") or "")
        except json.JSONDecodeError:
            pass
    return re.findall(r"[\w./-]+\.(?:py|js|ts|go|rb|java|c|cc|cpp|h|rs|php)",
                      txt or ""), ""


def rank(client, advisory: str, candidates: list[str],
         trace_hits: list[str] | None = None,
         revision_files: list[str] | None = None,
         poc: str = "") -> tuple[list[str], str]:
    """Ask the model to order candidates. Evidence is presented above the prose."""
    parts = []
    if trace_hits:
        parts.append("## Stack trace — files that were executing\n\n"
                     + "\n".join(trace_hits))
    if revision_files:
        shown = revision_files[:60]
        parts.append("## Regression range — files changed when the bug appeared\n\n"
                     + "\n".join(shown)
                     + ("\n... (%d more)" % (len(revision_files) - len(shown))
                        if len(revision_files) > len(shown) else ""))
    if poc:
        parts.append("## Triggering input / proof of concept\n\n```\n"
                     + poc[:1500] + "\n```")
    parts.append("## Advisory\n\n" + (advisory or "(none supplied)").strip())
    shown = candidates[:MAX_CANDIDATES]
    parts.append("## Candidate source files (%d)\n\n" % len(shown) + "\n".join(shown)
                 + ("\n... (%d more not shown)" % (len(candidates) - len(shown))
                    if len(candidates) > len(shown) else ""))
    parts.append("Which file contains the vulnerable code?")

    txt = client.chat([{"role": "system", "content": RANK_SYSTEM},
                       {"role": "user", "content": "\n\n".join(parts)}])
    ranked, why = _extract_ranked(txt)
    valid = [p for p in ranked if p in set(candidates)]
    return valid, why


def localize(client, target_dir: str, advisory: str, trace: str = "",
             poc: str = "", good_rev: str = "", bad_rev: str = "") -> dict:
    """Rank the files most likely to hold the flaw, using only symptom evidence.

    Returns {files, ranked, evidence, why}. `files` is the shortlist to hand
    downstream; `evidence` records which signals were actually available so the
    package can state how the file was chosen rather than asserting it.
    """
    candidates = enumerate_candidates(target_dir)
    if not candidates:
        return {"error": f"no source files found under {target_dir}"}

    hits = trace_files(trace, target_dir) if trace else []
    rev = narrow_by_revision(target_dir, good_rev, bad_rev)

    evidence = {
        "stack_trace_frames": len(parse_trace(trace)) if trace else 0,
        "stack_trace_files": hits,
        "revision_range_files": len(rev),
        "has_poc": bool(poc),
        "candidates": len(candidates),
    }

    # A trace frame inside a file we can patch is the strongest single signal
    # there is: that code was running when the boundary was crossed. Still ask
    # the model to order them, because the innermost frame is often a helper and
    # the fix belongs to its caller.
    pool = candidates
    if rev:
        inter = [c for c in candidates if c in set(rev)]
        if inter:
            pool = inter
            evidence["narrowed_by_revision"] = len(inter)

    try:
        ranked, why = rank(client, advisory, pool, hits, rev, poc)
    except Exception as e:
        # Evidence without a model is still better than an alphabetical scan.
        if hits:
            return {"files": hits[:5], "ranked": hits, "evidence": evidence,
                    "why": f"model ranking unavailable ({e}); using trace frames"}
        return {"error": f"ranking failed and no trace evidence to fall back on: {e}"}

    if not ranked:
        if hits:
            ranked = hits
            why = "model returned no usable ranking; using stack-trace frames"
        else:
            return {"error": "model returned no usable file ranking"}

    # !! CONTRADICTED BY EVIDENCE — DO NOT TRUST THIS BRANCH UNREVIEWED !!
    #
    # This forces trace frames to the top on the theory that a file the trace
    # proves was executing beats prose. ARVO bug 1076 (libxml2, MSan
    # use-of-uninitialized-value) falsifies that in the general case: the trace
    # names parserInternals.c and parser.c, while the developer's fix touches
    # SAX2.c, which does not appear in the trace at all. The crash SITE and the
    # fix SITE are different files — the uninitialised value was produced in one
    # place and consumed in another, which is the normal shape of a memory bug.
    #
    # On that bug this loop guarantees a wrong answer. Left in place deliberately
    # rather than silently redesigned: whether a trace frame should hard-override,
    # merely boost, or only inform the ranking is a design decision, and one that
    # wants measurement across many bugs rather than a fix chosen at 3am.
    # See the journal entry for 2026-07-31.
    for h in reversed(hits):
        if h in ranked:
            ranked.remove(h)
        ranked.insert(0, h)

    return {"files": ranked[:5], "ranked": ranked, "evidence": evidence, "why": why}
