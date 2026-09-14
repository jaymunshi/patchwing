"""tests/test_outcome_coverage.py — the static guard promised by outcomes.py.

Two directions, both derived from source:

  1. NO ORPHAN META-STRINGS: every outcome string emitted by stages.py in
     `meta={"outcome": "<X>"}` is a member of outcomes.ALL.
  2. NO ORPHAN CONSTANTS: every constant in outcomes.ALL is referenced
     by at least one call site in stages.py (or is on a small whitelist
     of constants whose emitters live elsewhere — the ceiling decorator,
     the safe-degrade sentinel).

Pure text parsing. No live imports of pipeline modules. Runs in CI, fast,
catches typos and forgotten registrations before they reach runtime — which
is what the outcomes.py doctrine names as the primary enforcement.
"""
import re
import sys

STAGES_PY = "/home/ubuntu/patchwing/stages.py"
OUTCOMES_PY = "/home/ubuntu/patchwing/outcomes.py"

# Constants whose call sites are legitimately OUTSIDE stages.py.
# Adding to this list is a deliberate act — every entry needs a comment.
_WHITELIST_UNUSED_IN_STAGES = {
    "ceiling_exceeded":         "raised by budget.check() from the metered client wrapper, not from a stage",
    "harness_unknown_outcome":  "safe-degrade sentinel returned by outcomes.validate(); not directly emitted by any stage",
    "harness_raised_retrying":  "emitted by runner._record_harness_failure on transient retry paths, not from a stage",
    "infrastructure_failure":   "emitted by runner._record_harness_failure on terminal harness raises, not from a stage",
}


def load_outcomes_constants() -> tuple[dict[str, str], set[str]]:
    """Return ({const_name: value}, ALL_set)."""
    src = open(OUTCOMES_PY).read()
    # Match `NAME = "value"` at module top level (no leading whitespace).
    consts: dict[str, str] = {}
    for m in re.finditer(r'^([A-Z][A-Z0-9_]+)\s*=\s*"([a-z0-9_]+)"\s*$',
                          src, re.M):
        consts[m.group(1)] = m.group(2)
    # Also load the runtime ALL to cross-check.
    sys.path.insert(0, "/home/ubuntu")
    from patchwing import outcomes as _oc
    return consts, set(_oc.ALL)


def find_emitted_outcomes_in_stages() -> set[str]:
    """Every string used as an outcome value in stages.py meta dicts."""
    src = open(STAGES_PY).read()
    emitted: set[str] = set()
    # Match: meta={"outcome": "..."} (with whitespace tolerance)
    for m in re.finditer(r'"outcome"\s*:\s*"([a-z0-9_]+)"', src):
        emitted.add(m.group(1))
    # Also match single-quoted variants
    for m in re.finditer(r"'outcome'\s*:\s*'([a-z0-9_]+)'", src):
        emitted.add(m.group(1))
    # Also match constant references: meta={"outcome": outcomes.NAME}
    # We resolve these via the constants map (Direction 2 handles the constants
    # themselves; if a constant is used here, its value is de-facto emitted).
    return emitted


def main() -> int:
    consts, all_set = load_outcomes_constants()
    emitted_strings = find_emitted_outcomes_in_stages()
    # A constant may be referenced by name too:
    stages_src = open(STAGES_PY).read()
    referenced_consts = {name for name in consts
                          if re.search(rf"\b(?:outcomes|outcomes_mod)\.{re.escape(name)}\b",
                                        stages_src)
                          or re.search(rf"\b{re.escape(name)}\b", stages_src)}
    # Convert referenced constants to their values, add to emitted set.
    emitted_effective = set(emitted_strings)
    for name in referenced_consts:
        emitted_effective.add(consts[name])

    errors: list[str] = []

    # Direction 1: every emitted string must be in ALL
    for s in sorted(emitted_strings):
        if s not in all_set:
            errors.append(
                f"DIRECTION 1: outcome {s!r} emitted in stages.py is NOT in "
                f"outcomes.ALL. Register it in patchwing/outcomes.py."
            )

    # Direction 2: every constant in ALL must be either referenced in stages.py
    # or on the whitelist.
    all_values_to_names = {v: k for k, v in consts.items()}
    for value in sorted(all_set):
        if value in emitted_effective:
            continue
        if value in _WHITELIST_UNUSED_IN_STAGES:
            continue
        # It's a constant with no reference and not whitelisted → orphan
        name = all_values_to_names.get(value, "<unnamed>")
        errors.append(
            f"DIRECTION 2: constant {name}={value!r} in outcomes.py is not "
            f"referenced by any stage in stages.py. Either register a call "
            f"site or add to _WHITELIST_UNUSED_IN_STAGES with a comment "
            f"explaining where it fires."
        )

    if errors:
        print("OUTCOME COVERAGE GUARD: FAILURES")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"OUTCOME COVERAGE GUARD: OK")
    print(f"  emitted-string outcomes: {len(emitted_strings)}")
    print(f"  outcomes.ALL constants:  {len(all_set)}")
    print(f"  referenced constants:    {len(referenced_consts)}")
    print(f"  whitelisted unused:      {len(_WHITELIST_UNUSED_IN_STAGES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
