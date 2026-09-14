"""Recursive provision loop — three binary checks (2026-08-08).

Each check:
  - runs against the CURRENTLY-COMMITTED image via sb.run_ephemeral (network=none)
  - is BINARY: exit code + stdout/stderr, no LLM grading, no judge
  - fails LOUD with a fix hint the model can act on

The checks live here, not in ecosystems/, because they consume the strategy
via its public interface (source_root_in_pod, expected_source_ref,
build_command). One place to see all three, one place to add a fourth.

Ownership boundary: ecosystems/ owns "what does the strategy know about this
target"; provision_checks owns "did the model actually set it up".
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CheckResult:
    ok: bool
    name: str
    cmd: str = ""
    expected: str = ""
    got: str = ""
    tail: str = ""
    fix_hint: str = ""

    def as_prompt_block(self) -> str:
        parts = [f"CHECK: {self.name}",
                 f"  ran: `{self.cmd}`" if self.cmd else "",
                 f"  expected: {self.expected}" if self.expected else "",
                 f"  got: {self.got}" if self.got else "",
                 "  tail:", "  ---",
                 *("  " + ln for ln in (self.tail or "").splitlines()[-40:]),
                 "  ---",
                 f"FIX: {self.fix_hint}" if self.fix_hint else ""]
        return "\n".join(p for p in parts if p)


_TAIL_BYTES = 1200


def _tail(text: str) -> str:
    if not text:
        return ""
    return text[-_TAIL_BYTES:]


def check_source_tree_exists(sb, strategy, pkg_name: str) -> CheckResult:
    """Check 1: source clone present at strategy.source_root_in_pod(sb)."""
    root = strategy.source_root_in_pod(sb)
    cmd = (f"test -d {root} && test -d {root}/.git && "
           f"test -f {root}/package.json && echo OK "
           f"|| (echo MISSING; ls -la {root}/.git {root}/package.json "
           f"2>&1 || true; ls -la {root} 2>&1 || true; "
           f"ls -la /pw/src 2>&1 || true)")
    r = sb.run_ephemeral(cmd, network="none", timeout_s=30)
    out = (r.stdout or "") + (r.stderr or "")
    ok = (r.returncode == 0) and ("OK" in out) and ("MISSING" not in out)
    if ok:
        return CheckResult(ok=True, name="source_tree_exists",
                           cmd=cmd, expected=f"{root}/.git + package.json",
                           got="present", tail="")
    return CheckResult(
        ok=False, name="source_tree_exists", cmd=cmd,
        expected=f"{root}/.git AND {root}/package.json",
        got="MISSING or unreadable",
        tail=_tail(out),
        fix_hint=(f"Clone the target repo INTO {root} (single dir), not "
                  f"/tmp or elsewhere. Ensure .git/ is intact — a shallow "
                  f"tarball or a rm -rf .git strip will fail this check."))


def check_source_ref_matches(sb, strategy, pkg_name: str,
                              affected_ref: str) -> CheckResult:
    """Check 2: source clone HEAD is at the expected git ref (derived from
    strategy.expected_source_ref(affected_ref))."""
    root = strategy.source_root_in_pod(sb)
    try:
        expected = strategy.expected_source_ref(affected_ref)
    except ValueError as e:
        # Strategy can't derive a ref — this is a prereq failure at the
        # loop level, but if it slips through, surface it as a check fail.
        return CheckResult(
            ok=False, name="source_ref_matches", cmd="",
            expected="(strategy could not derive)",
            got=str(e), tail="",
            fix_hint="Strategy.expected_source_ref raised — advisory "
                     "fixed_version is likely not semver-shaped.")
    cmd = (f"cd {root} && git describe --tags --exact-match HEAD 2>&1 "
           f"|| (echo '---STATUS---'; git status --short 2>&1; "
           f"echo '---TAGS-FIRST-30---'; "
           f"git tag --list 2>&1 | head -30; "
           f"echo '---HEAD---'; git log --oneline -1 2>&1)")
    r = sb.run_ephemeral(cmd, network="none", timeout_s=60)
    out_all = (r.stdout or "") + (r.stderr or "")
    # First line of stdout is either the tag name or an error.
    first = (r.stdout or "").strip().splitlines()[:1]
    got_first = first[0] if first else ""
    ok = (r.returncode == 0) and (got_first == expected)
    if ok:
        return CheckResult(ok=True, name="source_ref_matches",
                           cmd=cmd, expected=expected, got=got_first, tail="")
    return CheckResult(
        ok=False, name="source_ref_matches", cmd=cmd,
        expected=expected, got=got_first or "(no exact tag match)",
        tail=_tail(out_all),
        fix_hint=(f"Check out the AFFECTED version, not HEAD: "
                  f"`cd {root} && git fetch --depth=1 origin "
                  f"refs/tags/{expected}:refs/tags/{expected} && "
                  f"git checkout {expected}`. If the tag does not exist "
                  f"upstream, the affected version derivation is wrong "
                  f"— stop and report."))


def check_hermetic_smoke(sb, strategy, install_root: str,
                          pkg_name: str) -> CheckResult:
    """Check 3: strategy.build_command runs to completion under network=none.

    This is the truth-of-hermeticity check — the same command verify runs
    after each patch. Passing here means verify's own network=none isn't
    going to surprise us."""
    try:
        cmd = strategy.build_command(sb, install_root, pkg_name)
    except Exception as e:
        return CheckResult(
            ok=False, name="hermetic_smoke", cmd="",
            expected="strategy.build_command computed",
            got=type(e).__name__ + ": " + str(e)[:200],
            tail="",
            fix_hint="strategy.build_command raised — likely a monorepo "
                     "shape the current strategy can't map. Ensure the "
                     "target package.json has scripts.build OR the root "
                     "package.json declares workspaces covering the target.")
    r = sb.run_ephemeral(cmd, network="none", timeout_s=600)
    ok = (r.returncode == 0)
    if ok:
        return CheckResult(ok=True, name="hermetic_smoke",
                           cmd=cmd, expected="exit 0", got="exit 0", tail="")
    return CheckResult(
        ok=False, name="hermetic_smoke", cmd=cmd,
        expected="exit 0 under network=none",
        got=f"exit {r.returncode}",
        tail=_tail((r.stdout or "") + "\n---STDERR---\n" + (r.stderr or "")),
        fix_hint=("Build failed OR touched the network. Warm every cache "
                  "the build needs at provision time (npm install with "
                  "the vulnerable version pinned, source clone with "
                  "submodules if any). The build command IS the same one "
                  "verify will run."))


def run_checks(sb, strategy, pkg_name: str, install_root: str,
                affected_ref: str) -> list[CheckResult]:
    """Run all three checks in order. Return all results — do NOT short-circuit
    on first fail, so the model sees every failing check in one feedback
    round instead of thrashing one at a time."""
    return [
        check_source_tree_exists(sb, strategy, pkg_name),
        check_source_ref_matches(sb, strategy, pkg_name, affected_ref),
        check_hermetic_smoke(sb, strategy, install_root, pkg_name),
    ]


def format_failures_for_model(results: list[CheckResult]) -> str:
    """Build the user-message content fed back to the model when any check
    fails. Includes named checks, cmds, tails, fix hints — everything the
    model needs to act on without asking."""
    failed = [r for r in results if not r.ok]
    header = (f"Your last done:true was REJECTED — {len(failed)} of "
              f"{len(results)} binary check(s) failed against the committed "
              f"image. Fix the issue(s) below in the pod (via exec_in_pod), "
              f"then return done:true again — the loop will re-check.\n\n"
              f"These checks are ungameable: exit code + tail, no LLM "
              f"grading. Do not argue the verdict; fix the state.\n")
    return header + "\n\n".join(r.as_prompt_block() for r in failed)
