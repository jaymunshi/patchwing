"""Post-review ARVO commentary — reads the offline ARVO developer patch
and asks a single isolated model call to compare it against our patch.

GUARDRAIL (do not break):
  The ARVO developer patch flows only through this module and the one
  comparison model call it wires up. It NEVER reaches the patch seat, the
  verify stage, the advisory seat, or the four-state classifier. Nothing in
  the judging path imports from here. Grep-verifiable.

  Runs only when a finding has already reached `stage=review` with a final
  verdict. The reproducer is the sole judge.
"""
from __future__ import annotations

import json
import os
import re


ARVO_PATCH_DIR = "/tmp/ARVO-Meta/archive_data/patches"


class ArvoPatchNotFound(Exception):
    """The ARVO archive has no developer patch for this finding's arvo_id.

    The endpoint should return this to the caller as a clear error — do
    NOT fall through to silently writing an "unavailable" artifact from
    the endpoint. That path is only for bundle assembly when no
    arvo_comparison artifact exists at all."""

    def __init__(self, arvo_id: str, path: str):
        super().__init__(
            f"ARVO patch file not present at {path}. "
            f"The upstream archive is incomplete for {arvo_id}.")
        self.arvo_id = arvo_id
        self.path = path


class ArvoIdNotDerivable(Exception):
    """Finding's source_ref does not look like an ARVO id.

    Only ARVO-sourced findings can be compared. CVE findings, manual
    ingests, etc. have no ARVO patch to compare against."""


_ARVO_ID_RE = re.compile(r"(?:^|[-_/])(?:ARVO[-_]?)?(\d{2,7})\b", re.IGNORECASE)


def arvo_id_from_source_ref(source_ref: str) -> str:
    """Extract the numeric ARVO id from a finding's source_ref.

    Accepts "ARVO-1076", "arvo1076", "1076", ".../1076.diff", etc.
    Raises ArvoIdNotDerivable if no id can be found.
    """
    if not source_ref:
        raise ArvoIdNotDerivable("no source_ref on finding")
    m = _ARVO_ID_RE.search(source_ref)
    if not m:
        raise ArvoIdNotDerivable(
            f"cannot derive ARVO id from source_ref {source_ref!r}")
    return m.group(1)


def load_patch(arvo_id: str, root: str = ARVO_PATCH_DIR) -> bytes:
    """Read the ARVO developer patch bytes for a given id.

    Raises ArvoPatchNotFound if the file is absent — do not silently
    substitute. Bytes are returned as-read; no decoding, no normalization.
    """
    path = os.path.join(root, f"{arvo_id}.diff")
    if not os.path.isfile(path):
        raise ArvoPatchNotFound(arvo_id, path)
    with open(path, "rb") as fh:
        return fh.read()


COMPARISON_SYSTEM = """You are writing a plain-prose comparison between two
already-final patches for the same reported bug. You are NOT deciding whether
either patch is correct. The reproducer already decided that. Your output is
commentary, not a verdict. Nothing downstream reads what you write as a
decision.

Two patches are supplied:
  (a) OUR PATCH — the one PatchWing produced and that the container's
      four-state classifier already accepted (chain_proved).
  (b) THE ARVO DEVELOPER PATCH — the fix the upstream maintainer shipped.
      This is here only because the paper wants a side-by-side reading; it
      is NOT ground truth for what "the right fix" is.

You are also given the pristine crash trace and a summary of what our
investigation explored.

Write ONE plain-prose comparison in Markdown. Cover:

- Do the two patches touch the same file(s) and function(s)? Where do they
  agree?
- Where do they diverge, and why might they diverge? Consider: different
  layer (allocation site vs read site vs handler), different root-cause
  hypothesis, symptom vs cause fix, different scope (single-hunk vs
  sibling-scan across constructors).
- Did OUR fix address issues ARVO's did not, or vice versa? For example:
  ARVO shipped one hunk and we found the bug class recurs across sibling
  call sites and patched more — or the reverse. If the two patches don't
  even look like they're fixing the same defect, say so and be specific
  about what makes you think that.
- Are there downstream issues either patch leaves unaddressed that warrant
  a follow-up finding?

Rules:
- No verdicts. Do not say "ours is better" or "ARVO is better". State the
  facts of the diffs and let the reader draw conclusions.
- No confidence scores, no ratings, no pass/fail language.
- No JSON. Just Markdown prose.
- Do not start your output with the disclaimer — the harness prepends the
  provenance line and disclaimer. Start straight into the analysis with a
  heading like "## Files and functions".
- Prose only. If a diff quote is essential to your point, use fenced diff
  code blocks, but keep them short.
"""


def build_comparison_user_message(*,
                                  arvo_id: str,
                                  our_diff: str,
                                  arvo_diff: str,
                                  crash_trace: str,
                                  investigation_summary: str) -> str:
    """Assemble the one user message the comparison model sees."""
    return (
        f"# Finding: ARVO-{arvo_id}\n\n"
        "## Our patch (PatchWing, chain-proved by container)\n\n"
        "```diff\n"
        + our_diff.rstrip() + "\n"
        "```\n\n"
        "## ARVO developer patch (for reference only, NOT ground truth)\n\n"
        "```diff\n"
        + arvo_diff.rstrip() + "\n"
        "```\n\n"
        "## Pristine crash trace (what the reproducer originally showed)\n\n"
        "```\n"
        + (crash_trace or "(no crash trace on file)").rstrip() + "\n"
        "```\n\n"
        "## What our investigation explored\n\n"
        + (investigation_summary or "(no investigation summary available)")
        + "\n\n"
        "Now write the comparison as instructed."
    )


PROVENANCE_LINE = (
    "Bug origin: OSS-Fuzz, captured reproducibly via ARVO (n132/ARVO-Meta) "
    "as ARVO-{arvo_id}. Developer fix attached from ARVO archive."
)

DISCLAIMER_LINE = (
    "This is commentary, not a verdict; the reproducer already decided "
    "this finding."
)


def wrap_comparison_document(*, arvo_id: str, prose: str) -> str:
    """Prepend the provenance + disclaimer to the model's prose."""
    return (
        PROVENANCE_LINE.format(arvo_id=arvo_id) + "\n\n"
        + DISCLAIMER_LINE + "\n\n"
        + prose.strip() + "\n"
    )


def summarize_investigation(events: list) -> str:
    """Compact prose-friendly rollup of what the investigation loop did.

    Reads-only over the events rows passed in. Returns a small chunk of
    text describing what the model explored — file reads, greps, function
    lookups, patch attempts. Do NOT include tool outputs (too big); just
    the call log."""
    if not events:
        return "(no investigation loop ran for this finding)"

    per_turn: dict[int, list[str]] = {}
    tool_totals: dict[str, int] = {}
    patch_attempts = 0
    duplicates = 0
    chain_proved_at = None

    for ev in events:
        kind = ev["kind"] or ""
        if not (kind.startswith("investigation_")
                or kind.startswith("loop_")):
            continue
        try:
            m = json.loads(ev["meta"] or "{}")
        except (json.JSONDecodeError, TypeError):
            m = {}
        turn = m.get("turn")

        if kind == "investigation_tool_call":
            tool = m.get("tool", "?")
            tool_totals[tool] = tool_totals.get(tool, 0) + 1
            args = m.get("args", {}) or {}
            desc = (args.get("name") or args.get("path")
                    or args.get("pattern") or "")
            if turn is not None:
                per_turn.setdefault(int(turn), []).append(
                    f"{tool}({str(desc)[:80]})")
        elif kind == "investigation_patch_returned":
            patch_attempts += 1
        elif kind == "investigation_duplicate_call":
            duplicates += 1
        elif kind == "investigation_chain_proved":
            chain_proved_at = m.get("turn")

    lines: list[str] = []
    turns_used = len(per_turn) or 0
    total_tool_calls = sum(tool_totals.values())
    lines.append(
        f"Investigation ran for {turns_used} turn(s), {total_tool_calls} "
        f"tool call(s), {patch_attempts} patch attempt(s), "
        f"{duplicates} duplicate-call nudge(s). "
        + (f"Chain-proved at turn {chain_proved_at}."
           if chain_proved_at is not None else
           "Chain was not proved through the investigation loop."))
    if tool_totals:
        breakdown = ", ".join(
            f"{k}={v}" for k, v in sorted(tool_totals.items()))
        lines.append(f"Tool mix: {breakdown}.")
    if per_turn:
        lines.append("Per-turn tool calls (compressed):")
        for t in sorted(per_turn)[:25]:
            calls = per_turn[t]
            lines.append(f"  T{t}: " + "; ".join(calls[:10])
                         + ("  …" if len(calls) > 10 else ""))
    return "\n".join(lines)
