"""Search/replace editing — how the fix-writer changes code.

Whole-file regeneration is retired. It failed on a 53 KB Jinja2 file and the ARVO
targets are larger still (SAX2.c is 86 KB against a 65 KB patch limit), so the
approach did not scale and never would have.

**Why search/replace and not unified diff.** Models are unreliable at hunk headers
and line arithmetic, and the failure is nasty in both directions: a malformed diff
either fails to apply, or — worse — applies cleanly AT THE WRONG OFFSET, silently
corrupting code far from the bug. Both outcomes surface as "the model failed to fix
it". Search/replace removes the whole class: an exact snippet to find and an exact
replacement, with no line numbers anywhere.

**Uniqueness is enforced, not assumed.** A search string matching twice is rejected
rather than applied first-match-wins. In C especially, a plausible-looking snippet
(`    if (ret == NULL)`) can occur dozens of times, and first-match-wins would patch
an unrelated function while reporting success. Zero matches and multiple matches are
both refusals, and both are *harness* outcomes rather than judgements about the fix.

Block format — the widely-used convention, so models emit it reliably:

    <<<<<<< SEARCH
    exact text to find
    =======
    text to replace it with
    >>>>>>> REPLACE
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

BLOCK_RE = re.compile(
    r"<{5,9}\s*SEARCH\s*\n(.*?)\n?={5,9}\s*\n(.*?)\n?>{5,9}\s*REPLACE",
    re.S,
)


class EditError(Exception):
    """A block could not be applied. Always a harness/format outcome, never a
    statement about whether the fix was correct."""


class AmbiguousSearchError(EditError):
    """A SEARCH block matched more than once. Recoverable at the caller — the
    model can be told exactly what happened and asked once more (see
    stages.patch's retry loop, parallel to models.chat_json's JSON repair). A
    subclass so the caller can catch this specifically without string-matching
    the message."""

    def __init__(self, message: str, *, block_index: int, total_blocks: int,
                 match_count: int, search: str):
        super().__init__(message)
        self.block_index = block_index
        self.total_blocks = total_blocks
        self.match_count = match_count
        self.search = search


class EditsWrongTypeError(EditError):
    """`edits` field was not a string. Schema violation, not ambiguity.

    A separate subclass because the runner treats this as a terminal,
    first-class model-output failure (PATCH_EDITS_WRONG_TYPE) — never as
    infrastructure and never auto-retried. A model that returned a list
    once will very likely return a list again."""

    def __init__(self, actual_type: str):
        super().__init__(
            f"edits field must be a string of SEARCH/REPLACE blocks, "
            f"got {actual_type}")
        self.actual_type = actual_type


@dataclass
class Block:
    search: str
    replace: str

    @property
    def is_deletion(self) -> bool:
        return self.replace.strip() == ""


@dataclass
class ApplyResult:
    text: str
    applied: int = 0
    blocks: list[Block] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def parse(text: str) -> list[Block]:
    """Pull search/replace blocks out of a model response.

    Tolerant of surrounding prose and fenced code, because models wrap output even
    when told not to; intolerant of anything ambiguous inside a block.

    Type-strict on `text`: the schema says `edits` is a string. If the model
    returns a list, dict, or anything else, raise EditsWrongTypeError so the
    patch stage records a first-class outcome instead of crashing. `None` is
    preserved as-empty-string for backwards compatibility with callers that
    pass `.get("edits")` without a default.
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise EditsWrongTypeError(type(text).__name__)
    blocks = [Block(search=m.group(1), replace=m.group(2))
              for m in BLOCK_RE.finditer(text)]
    return [b for b in blocks if b.search.strip()]


def apply(source: str, blocks: list[Block]) -> ApplyResult:
    """Apply blocks to `source`, refusing anything not exactly locatable.

    Blocks are applied in sequence against the evolving text, so a later block may
    legitimately target text an earlier one produced.
    """
    if not blocks:
        raise EditError("no search/replace blocks found in the response")

    text = source
    res = ApplyResult(text=source)
    for i, b in enumerate(blocks, 1):
        n = text.count(b.search)
        if n == 0:
            # Whitespace drift is the common cause, so say so — it is actionable
            # in a retry, unlike a bare "not found".
            squashed = re.sub(r"\s+", " ", b.search.strip())
            hint = ""
            if squashed and re.sub(r"\s+", " ", text).count(squashed) > 0:
                hint = (" The text is present but the whitespace differs — copy the "
                        "region verbatim, including indentation.")
            raise EditError(
                f"block {i}/{len(blocks)}: SEARCH text not found in the file.{hint} "
                f"First line was: {b.search.splitlines()[0][:100]!r}")
        if n > 1:
            raise AmbiguousSearchError(
                f"block {i}/{len(blocks)}: SEARCH text occurs {n} times and is "
                f"ambiguous. Applying it would patch an arbitrary one of them. "
                f"Include enough surrounding context to make it unique. "
                f"First line was: {b.search.splitlines()[0][:100]!r}",
                block_index=i, total_blocks=len(blocks), match_count=n,
                search=b.search)
        text = text.replace(b.search, b.replace, 1)
        res.applied += 1

    if text == source:
        raise EditError("blocks applied but the file is unchanged — the replacement "
                        "is identical to the search text")
    res.text = text
    res.blocks = blocks
    return res


def window(source: str, anchors: list[str], radius: int = 60) -> tuple[str, int, int]:
    """A slice of the file around the region of interest, with line numbers.

    The fix-writer cannot be shown 86 KB of C. It gets a window instead.

    NOTE: this makes the localizer's output granularity FILE *AND REGION*. Region
    selection is a second capability riding on symptom.py's file ranking and it is
    entirely UNMEASURED — a wrong window produces a fix-writer that cannot see the
    bug, which is a localization failure that will present as a patch failure.
    Returns (text, first_line, last_line), 1-indexed inclusive.
    """
    lines = source.splitlines()
    if not lines:
        return "", 0, 0
    hit = None
    for a in anchors:
        if not a:
            continue
        for i, ln in enumerate(lines):
            if a in ln:
                hit = i
                break
        if hit is not None:
            break
    if hit is None:
        # No anchor found: show the head rather than an arbitrary slice, and let
        # the caller see the line range so the choice is visible in the package.
        lo, hi = 0, min(len(lines), radius * 2)
    else:
        lo = max(0, hit - radius)
        hi = min(len(lines), hit + radius)
    return "\n".join(lines[lo:hi]), lo + 1, hi


def describe(blocks: list[Block]) -> str:
    total = sum(len(b.search.splitlines()) for b in blocks)
    return (f"{len(blocks)} search/replace block(s), "
            f"{total} line(s) of context matched")


def to_unified_diff(path: str, before: str, after: str) -> str:
    """Render the applied change as a unified diff — for the EVIDENCE PACKAGE only.

    Reviewers read diffs; models write them badly. Generating it here, from text we
    already applied, gives the reader a familiar artifact with none of the risk of
    asking a model for one.
    """
    import difflib
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}", n=3))
