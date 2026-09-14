"""Enumerate terminating paths in stages.py by parsing it, not by grepping it.

Regex over source is how the two earlier defects got through. `@@` headers named an
enclosing function and were read as the changed one; "every path now sets a value"
was read off a handful of matches. Both were LOCAL signals inferred to be GLOBAL
properties. A parser does not infer: it either finds every ``StageResult.*`` call
node or the file does not parse.

This module is deliberately dumb — it reports what is there. The judging lives in the
tests that import it, so a change to the standard cannot quietly change the census.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "patchwing")
STAGES_PY = os.path.join(PKG, "stages.py")

KINDS = frozenset({"ok", "retry", "blocked", "reject", "fail"})


@dataclass(frozen=True)
class Path:
    """One terminating path: a single ``StageResult.<kind>(...)`` construction."""
    lineno: int
    func: str          # enclosing function, innermost
    kind: str          # ok | retry | blocked | reject | fail
    outcome: str | None   # value of meta["outcome"], or None if absent
    dynamic: bool      # meta["outcome"] present but not a literal string
    has_artifacts: bool = False   # passes artifacts=...
    post_execution: bool = False  # sits after something was RUN in this function

    def describe(self) -> str:
        return f"stages.py:{self.lineno} in {self.func}() -> StageResult.{self.kind}"


def _owners(tree: ast.AST) -> dict[int, str]:
    """Map line number -> innermost enclosing function name."""
    owner: dict[int, tuple[str, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                prev = owner.get(ln)
                if prev is None or node.lineno > prev[1]:
                    owner[ln] = (node.name, node.lineno)
    return {ln: name for ln, (name, _) in owner.items()}


def _first_execution_line(tree: ast.AST) -> dict[str, int]:
    """func name -> line of the first ``<something>.run(...)`` inside it.

    That call is where output starts existing. Anything after it is pronouncing a
    verdict on something that ran, so the output is available to attach.

    LEXICAL, not a control-flow analysis: a path after the first run might, on some
    branch, have had nothing execute. That direction of error is the safe one — it
    over-reports and makes a human look. The opposite heuristic would quietly bless
    a rejection whose evidence was discarded, which is the defect being guarded.
    """
    first: dict[str, int] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        runs = [n.lineno for n in ast.walk(fn)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "run"]
        if runs:
            first[fn.name] = min(runs)
    return first


def terminating_paths(src_path: str = STAGES_PY) -> list[Path]:
    with open(src_path, encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src, filename=src_path)
    owner = _owners(tree)
    first_run = _first_execution_line(tree)

    found: list[Path] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute)
                and fn.attr in KINDS
                and isinstance(fn.value, ast.Name)
                and fn.value.id == "StageResult"):
            continue

        outcome, dynamic = None, False
        for kw in node.keywords:
            if kw.arg != "meta" or not isinstance(kw.value, ast.Dict):
                continue
            for k, v in zip(kw.value.keys, kw.value.values):
                if isinstance(k, ast.Constant) and k.value == "outcome":
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        outcome = v.value
                    else:
                        dynamic = True

        func = owner.get(node.lineno, "<module>")
        found.append(Path(
            lineno=node.lineno, func=func, kind=fn.attr,
            outcome=outcome, dynamic=dynamic,
            has_artifacts=any(kw.arg == "artifacts" for kw in node.keywords),
            post_execution=node.lineno > first_run.get(func, 1 << 30)))

    found.sort(key=lambda p: p.lineno)
    return found


def outcome_literals_in_package() -> dict[str, set[str]]:
    """Every ``"outcome": "<literal>"`` dict entry in the package, keyed by file.

    Not every outcome is emitted by a stage. ``runner._advance`` records one when a
    stage RAISES — the case that never builds a StageResult, and therefore the case
    the path walker structurally cannot see. Without this, the no-slack check would
    call those constants unused and the honest fix would look like deleting them.
    """
    out: dict[str, set[str]] = {}
    for name in sorted(os.listdir(PKG)):
        if not name.endswith(".py"):
            continue
        p = os.path.join(PKG, name)
        try:
            with open(p, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=p)
        except SyntaxError:
            continue
        from patchwing import outcomes as _o
        found = set()
        for node in ast.walk(tree):
            # 1. A literal under an "outcome" key — how stages.py writes them.
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if (isinstance(k, ast.Constant) and k.value == "outcome"
                            and isinstance(v, ast.Constant)
                            and isinstance(v.value, str)):
                        found.add(v.value)
            # 2. ANY reference to a declared constant, anywhere in the file.
            #    Not just inside a dict: runner.py picks the value into a local
            #    first, so the dict entry is `{"outcome": outcome}` — an ast.Name
            #    whose value is invisible here. Scoping this to dict literals made
            #    the two harness constants read as unused, and the tidy-looking fix
            #    would have been to delete the outcomes that close the hole.
            elif isinstance(node, ast.Attribute) and node.attr.isupper():
                resolved = getattr(_o, node.attr, None)
                if isinstance(resolved, str):
                    found.add(resolved)
        if found:
            out[name] = found
    return out


def construction_sites() -> list[str]:
    """Every .py in the package that constructs a StageResult.

    The guard reads ONE file. If a second file ever starts building results, a guard
    scoped to stages.py would pass while paths went unlabelled elsewhere — a check
    that stops being a check without anyone editing it.
    """
    sites = []
    for name in sorted(os.listdir(PKG)):
        if not name.endswith(".py"):
            continue
        p = os.path.join(PKG, name)
        try:
            with open(p, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=p)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in KINDS
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "StageResult"):
                sites.append(name)
                break
    return sites
