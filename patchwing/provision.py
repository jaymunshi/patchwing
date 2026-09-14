"""Provision stage — closed-loop pod bring-up + commit.

Sibling to `stages._run_investigation_loop`. Shares the closed-loop shape
(model returns tool_calls OR a terminator per turn; loop dispatches tools
and feeds results back) but has its own terminator:
    {"done": true, "target_url": "...", "reproduce_command": "..."}
instead of the patch loop's chain-prove.

**Why a separate loop instead of one big parameterized one.**
The patch loop's success is external pod state (chain-proved via
apply/build/rebuild/re-run of the reproducer). The provision loop's
success is INTERNAL to the model's own answer (target_url + evidence
rules matched via http_probe). Fusing them would require the parent
loop to hold BOTH terminator shapes and branch on which is active at
the deepest hot-loop of every turn. Two functions sharing a pattern is
cheaper than one function with two brains.

**Guardrail.** Provision writes NO reproducer_lock. The lock is written
only by @stage("reproduce"); provision's job stops at "here's a pod
image + reproduce command + http-block for the spec." An assertion in
the outer stage body enforces this at return time.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from dataclasses import dataclass

from . import budget as budget_mod
from .sandbox import SandboxError
from .tools import ToolError


# --- exceptions -----------------------------------------------------------
# Sibling of stages._InvestigationBudgetExhausted etc. Names mirror the
# patch loop's exceptions so callers can pattern-match on shape.

class ProvisionInvalidSpec(Exception):
    """HTTP-kind provision refuses to run: spec violates a hard contract
    (e.g. no evidence_rules declared). Actionable operator error."""


class ProvisionGaveUp(Exception):
    """Model returned {"give_up": "..."} — cannot proceed."""


class ProvisionBudgetExhausted(Exception):
    """USD cap tripped mid-loop."""


class ProvisionCommitFailed(Exception):
    """`podman commit` failed OR timed out. Distinct from
    ProvisionGaveUp (which is a model give-up) — this is an
    INFRA fault. Routes to provision_commit_failed outcome so
    the operator can debug commit speed / disk / storage
    driver without conflating it with model behaviour."""
    pass


class ProvisionBootstrapFailed(Exception):
    """Deterministic bootstrap (before first model turn) hit a
    non-zero step. Preserves the failing step + stderr tail so
    the operator can see WHICH prep command failed."""
    pass


class ProvisionLoopStuck(Exception):
    """Same (check_name, exit_code, tail_hash) signature seen K
    consecutive times across check rounds. Aborts before max_turns
    on the definition-of-insanity failure mode: identical build
    fail repeated, no progress."""
    pass


class ProvisionLoopExhausted(Exception):
    """The recursive provision loop exhausted turns/USD while at
    least one binary check was still failing. Preserves the last
    check's failure tail so operators see WHAT was rejected."""
    pass


# Legacy alias — retained for import-compat during refactor. Delete
# once nothing raises the old name (Chunk 2 removed all raises).
ProvisionExhausted = ProvisionLoopExhausted

class _RETIRED_ProvisionExhausted(Exception):
    """max_turns cap tripped without a terminator."""


# --- tools ---------------------------------------------------------------
# Every tool takes `sb` (a Sandbox) as first arg, matching tools.py.
# Every tool returns a string — what the model sees back. Errors raise
# ToolError, which the loop feeds back as an error result on that call.

# Bytes cap on tool output the model sees back. Prevents a runaway
# install_package from blowing the context window.
_TOOL_OUTPUT_MAX = 20000


def _clip(text: str, kind: str = "output") -> str:
    if len(text) <= _TOOL_OUTPUT_MAX:
        return text
    return (text[:_TOOL_OUTPUT_MAX]
            + f"\n\n[... truncated at {_TOOL_OUTPUT_MAX} bytes; full {kind}"
              f" was {len(text)} bytes]")


EXEC_IN_POD_TIMEOUT_MAX = 1800   # 30 min hard cap; longer needs a spec change


def exec_in_pod(sb, cmd: str, timeout_s=None) -> str:
    """Run a shell command inside the pod. Returns combined stdout+stderr
    plus the exit code. NEVER raises on non-zero exit — the exit code is
    data the model needs to see.

    `timeout_s` is REQUIRED (int seconds, 1..1800). No default. The model
    must pick a number that fits the command — this forces a synchronous
    contract, so one turn covers the operation instead of spawning it in
    the background and polling in a loop. Values above 1800 are silently
    clamped to 1800 (30 min hard cap). Missing / non-int / <1 raises
    ToolError which the loop feeds back so the model retries. On timeout
    the output is prefixed `[TIMED OUT after Ns]` and returncode is -1 —
    the process was killed; retry with a bigger number if needed."""
    if not isinstance(cmd, str) or not cmd.strip():
        raise ToolError("exec_in_pod: cmd must be a non-empty string")
    if timeout_s is None:
        raise ToolError(
            "exec_in_pod: timeout_s is required (int seconds, 1..1800). "
            "Pick a number that fits the command — short probes: 30-60, "
            "package installs: 300, mvn/gradle builds: 1200-1800.")
    try:
        _to = int(timeout_s)
    except (TypeError, ValueError):
        raise ToolError(
            f"exec_in_pod: timeout_s must be an integer, got {timeout_s!r}")
    if _to < 1:
        raise ToolError(
            f"exec_in_pod: timeout_s must be >= 1, got {_to}")
    _to = min(EXEC_IN_POD_TIMEOUT_MAX, _to)
    try:
        r = sb.run(cmd, timeout_s=_to)
    except SandboxError as e:
        raise ToolError(f"exec_in_pod: {e}")
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    prefix = (f"[TIMED OUT after {_to}s] "
              if getattr(r, "timed_out", False) else "")
    return _clip(
        f"{prefix}exit {r.returncode} in {round(r.duration_s, 2)}s\n{out}",
        kind="command output")


def write_file_to_pod(sb, path: str, content: str) -> str:
    """Write content to a path inside the pod. Parent dirs must exist —
    the model can `exec_in_pod('mkdir -p ...')` first if needed. Returns
    a confirmation with the byte count."""
    if not isinstance(path, str) or not path.strip():
        raise ToolError("write_file_to_pod: path must be a non-empty string")
    if not isinstance(content, str):
        raise ToolError("write_file_to_pod: content must be a string")
    try:
        sb.write(path, content)
    except SandboxError as e:
        raise ToolError(f"write_file_to_pod({path!r}): {e}")
    return f"wrote {len(content)} bytes to {path}"


def install_package(sb, name: str, timeout_s: int = 600) -> str:
    """Install a Debian/Ubuntu package via apt-get. Assumes the base image
    has apt available (ubuntu:22.04 default). Runs update on first invocation
    per pod via an idempotent marker file.

    `timeout_s` defaults to 600 (10 min) — enough for a normal install
    on a fast VM. Slow-network VMs may need 1800+ for the first call
    (apt-get update + install can take 5+ min end-to-end); pass it
    explicitly. LLM callers omit it; deterministic template recipes
    bump per call."""
    if not isinstance(name, str) or not name.strip():
        raise ToolError("install_package: name must be a non-empty string")
    # Package names come from the model — refuse anything that could inject
    # a second command via metachars. apt package names are letters/digits/
    # dot/plus/hyphen; nothing else. This is defensive against the model
    # returning "openjdk-8-jdk && curl attacker" as the "name".
    if any(c in name for c in "; \t\n$`|&()<>\"'\\"):
        raise ToolError(
            f"install_package: {name!r} contains shell metacharacters — "
            f"apt package names must be [A-Za-z0-9.+_-]+ only")
    quoted = shlex.quote(name)
    cmd = (
        # idempotent apt-get update — the marker file is our own; if apt-get
        # update fails, that surfaces to the model as the error it is.
        "sh -c '"
        "if [ ! -f /tmp/.patchwing_apt_updated ]; then "
        "  DEBIAN_FRONTEND=noninteractive apt-get update -qq "
        "  && touch /tmp/.patchwing_apt_updated; "
        "fi && "
        f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {quoted}"
        "'")
    try:
        r = sb.run(cmd, timeout_s=int(timeout_s) if timeout_s else 600)
    except SandboxError as e:
        raise ToolError(f"install_package({name!r}): {e}")
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    return _clip(
        f"exit {r.returncode} installing {name}\n{out}", kind="apt output")


def http_probe(sb, url: str, method: str = "GET",
               headers: dict | None = None, body: str = "") -> str:
    """Send an HTTP request FROM INSIDE the pod, return status + body.

    Runs curl inside the pod so the URL can be `http://127.0.0.1:PORT/...`
    against a service the model just started. Same-pod probing means the
    reproduce command in the final spec (which will also run inside the
    pod-committed image) hits the same URL from the same vantage point —
    no host:port drift between provision and reproduce.

    Response is returned in a plain text envelope the model can grep:
        HTTP <status>
        <headers, one per line>

        <body, truncated>
    """
    if not isinstance(url, str) or not url.strip():
        raise ToolError("http_probe: url must be a non-empty string")
    method = (method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"):
        raise ToolError(f"http_probe: unsupported method {method!r}")
    # -s silent; -S show errors; -k skip TLS verify (local target); -i
    # include response headers; -w bakes a marker on the last line so we
    # can split. --max-time defends against a target that answers slowly.
    parts = ["curl", "-sSki", "--max-time", "30",
             "-o", "/tmp/.patchwing_probe_body",
             "-w", "PATCHWING_HTTP_STATUS=%{http_code}\\n",
             "-X", method]
    for k, v in (headers or {}).items():
        parts += ["-H", f"{k}: {v}"]
    if body:
        parts += ["--data-binary", body]
    parts.append(url)
    cmd = " ".join(shlex.quote(p) for p in parts)
    # cat the body after — one round-trip, no separate file read.
    cmd = f"{cmd}; echo '---PATCHWING_HTTP_BODY---'; cat /tmp/.patchwing_probe_body"
    try:
        r = sb.run(cmd, timeout_s=40)
    except SandboxError as e:
        raise ToolError(f"http_probe({url!r}): {e}")
    out = r.stdout or ""
    err = r.stderr or ""
    if r.returncode != 0 and "PATCHWING_HTTP_STATUS" not in out:
        # curl itself failed (couldn't connect, DNS, TLS, etc). Feed the
        # error text back — that's how the model learns "not listening yet".
        return _clip(f"http_probe transport error (curl exit {r.returncode}): "
                     f"{err.strip()[:400]}", kind="transport error")
    return _clip(out, kind="http response")


PROVISION_TOOLS = {
    "exec_in_pod":       exec_in_pod,
    "write_file_to_pod": write_file_to_pod,
    "install_package":   install_package,
    "http_probe":        http_probe,
}


# Diagnostic — pulls hostnames out of shell commands so the audit trail
# records every outbound host the provision loop touches. No enforcement
# — the SandboxConfig.provision_network gates the network on/off. This
# just observes so the operator can build a real allowlist from the
# hosts that actually appear across real runs. Patterns cover the shapes
# a code model typically emits: curl/wget URLs, git clone URLs, pip
# indexes, apt sources. False negatives are fine — we care about
# knowing what hits when Kimi does the obvious things.
_HOST_RE = re.compile(
    r"""(?xi)
    (?:
        https?://                          # http://X or https://X
      | git(?:\+ssh)?://                    # git:// / git+ssh://
      | ssh://[\w.-]+@                      # ssh://user@X
      | git@                                # git@X (scp-like git URL)
      | wget\s+[^|;&\n]*?                   # wget ... URL
      | curl\s+[^|;&\n]*?                   # curl ... URL
    )
    ([a-z0-9][a-z0-9._-]*\.[a-z]{2,})       # the hostname (allow x.y)
    """)


def _extract_hosts_from_cmd(cmd: str) -> set:
    """Best-effort hostname extraction from a shell command string.
    Returns a lowercase set. Never raises — this is diagnostic."""
    if not isinstance(cmd, str) or not cmd:
        return set()
    return set(m.lower() for m in _HOST_RE.findall(cmd))


def _normalize_tool_call(call):
    """Accept both the legacy `{tool, args}` shape and OpenAI's
    ChatCompletions `{function: {name, arguments}}` shape. Return
    the legacy shape so the loop's downstream dispatch is unchanged.

    Kimi K2.7-Code emits OpenAI-shaped calls by default (that's the
    format its function-calling fine-tune targets). Without this
    normalizer every Kimi turn read as `tool=''`, deduped against the
    same empty-key seen_calls entry, and the whole loop burned 40 turns
    with 1 real tool call (observed on the first live Struts run).

    Also aliases `command` → `cmd` for exec_in_pod: the tool spec says
    `cmd`, but Kimi (and other code models) frequently pass `command`
    — pure ergonomic normalization, no semantic change."""
    if not isinstance(call, dict):
        return call
    # OpenAI shape → legacy shape
    if "function" in call and isinstance(call["function"], dict):
        fn = call["function"]
        args = fn.get("arguments", {})
        # OpenAI encodes arguments as a JSON STRING per spec
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {}
        if not isinstance(args, dict):
            args = {}
        call = {"tool": str(fn.get("name", "")), "args": args}
    # Alias for exec_in_pod: command → cmd (only if cmd not already set)
    if (call.get("tool") == "exec_in_pod"
            and isinstance(call.get("args"), dict)
            and "command" in call["args"] and "cmd" not in call["args"]):
        call["args"]["cmd"] = call["args"].pop("command")
    return call


PROVISION_TOOL_SPEC = """You can call any of these tools. Return them as
`tool_calls` in your JSON reply.

- exec_in_pod(cmd, timeout_s): run a shell command inside the pod.
    args: {"cmd": "ls -la /workspace", "timeout_s": 30}
    Returns combined stdout+stderr plus exit code. Non-zero exit is NOT
    an error — read the output and adjust.
    **timeout_s is REQUIRED** — int seconds, 1..1800 (30 min). Pick a
    number that fits the command:
      * quick reads/greps/lists → 30-60
      * git clone / wget / curl of large tarballs → 300-600
      * apt-get install of large stacks (JDK etc) → 900-1800
      * mvn/gradle/make/cargo builds → 1200-1800
    The command runs synchronously in-turn; there is no background job
    and nothing to poll. Output is prefixed `[TIMED OUT after Ns]` if
    the wall clock ran out — the process was killed. Retry with a
    bigger number if needed.
- write_file_to_pod(path, content): write a file inside the pod. Parent
    dirs must exist — mkdir first if needed.
    args: {"path": "/workspace/run.sh", "content": "#!/bin/sh\\nexec ..."}
- install_package(name): apt-get install a Debian package. Base image is
    ubuntu:22.04 unless you rebuilt it yourself.
    args: {"name": "openjdk-8-jdk"}
- http_probe(url, method='GET', headers, body): send an HTTP request from
    inside the pod. Use http://127.0.0.1:PORT/... against a service you
    just started. Response envelope starts with 'HTTP <status>' and the
    body follows a '---PATCHWING_HTTP_BODY---' marker.
    args: {"url": "http://127.0.0.1:8080/eval?cmd=id"}
    optional: {"method": "POST", "headers": {"content-type": "..."},
               "body": "..."}

You may call up to 5 tools per turn."""


# --- initial-message + terminator helpers --------------------------------

PROVISION_SYSTEM = """You are a build engineer bringing up a target so that
a security reproducer can fire the vulnerability under test.

You have a fresh pod running a base image (ubuntu:22.04 unless you
change it). Your job:

  1. Install everything the target needs (JDK, Maven, package
     managers, git, etc) via install_package and exec_in_pod.
  2. Fetch and build the vulnerable version of the target
     (git clone + checkout the parent of the fix commit + build).
  3. Start the vulnerable service listening on a port you choose.
  4. Fire the reproducer command against it using http_probe and
     confirm the response matches the operator-authored evidence rules
     (regex patterns and side-channel signatures — you'll see them in
     the initial message).
  5. When the target is up and the reproducer fires a matching
     signature, return:
         {"done": true,
          "target_url": "http://127.0.0.1:PORT/path...",
          "reproduce_command": "curl -sSki http://127.0.0.1:PORT/... "
                               "; cat /tmp/side_channel_marker"}
     The reproduce command is what will be run inside the committed
     image on every future reproduce cycle, so it must (a) start any
     background service if needed, (b) probe the endpoint, (c) surface
     evidence (response body + any side-channel file contents) in its
     stdout. Design it to run to completion in under 60s.

If you decide the target cannot be brought up (e.g. deps are permanently
unresolvable), return {"give_up": "<one-sentence reason>"}.

Never write reproducer_lock, spec, or draft_spec files — those are
written by the pipeline around you, not by any command you run.

Respond in JSON only. Either request tool_calls, or return the done or
give_up terminator. Do not mix tool_calls and done in the same reply.

Tool-argument naming: use the exact argument names shown above. For
exec_in_pod the argument is `cmd`, NOT `command`. Both the legacy
{"tool":"exec_in_pod","args":{"cmd":"..."}} shape and the OpenAI
{"function":{"name":"exec_in_pod","arguments":"{\\"cmd\\":\\"...\\"}"}}
shape are accepted; pick either but keep the arg name `cmd`.

EVIDENCE SIGNAL PROTOCOL - how your reproduce_command MUST talk to
the classifier. Every operator-authored evidence rule has a NAME and a
KIND. Your reproducer must emit each rule's signal using the NAME as
the marker key - never invent ad-hoc names like side_channel_marker
or ---MARKER---. The classifier looks for the EXACT rule name.

For each side_channel_flag rule, emit ONE of these forms in your
reproducer's stdout:

  1. CANONICAL (preferred, unambiguous):
       #PW_SC <name>=<value>
     e.g. echo '#PW_SC vite_leak_pwned=True'

  2. JSON body key/value (if your target already returns JSON):
       "<name>":"<value>"

  3. Trailer key:value line:
       <name>: <value>

Emit #PW_SC <name>=True (or the rule's positive pattern) when the
bug REPRODUCES. Emit #PW_SC <name>=False (or any non-positive value)
when it does NOT. Silent absence of the marker is treated as
HARNESS_FAULT - the classifier refuses to call GREEN when a declared
rule produced no reading at all.

The per-run initial message includes the exact rule names + patterns
you must emit for THIS finding.

REPRODUCER CONTRACT (Chunk 3, revised design). Your `done` terminator
must return `reproducer_script` (the shell script BYTES) and
`install_root` (absolute path in pod to the running installed package),
NOT a `reproduce_command` string. The pipeline materializes your bytes
to /reproduce.pw.sh (canonical, chmod +x), sets commands.reproduce =
"bash /reproduce.pw.sh", and freezes /reproduce.pw.sh via the wall.
This gives the wall one hashable artifact that decides red/green.
If your reproducer needs extra input files (poison zips, HTML
fixtures), also return `reproducer_extra_files: [{path, bytes}]` —
each will be materialized + frozen alongside the script.

PROVISION MODES. The initial message tells you which mode this
finding is in — one of the two:

  * TEMPLATE mode: your pod is pre-provisioned by a named template. The
    template documents its install layout (paths under /opt/<name>/ or
    similar). Read those paths from the draft-spec's http block (endpoint,
    url) and any template metadata surfaced in the initial message. Do
    NOT clone source under /pw/src/. Do NOT install the target package
    yourself — it's already installed at the template's documented path.

  * STRATEGY mode: no template. You MUST clone the target's source repo
    to /pw/src/<pkgname>/ (single directory under /pw/src). The
    strategy's build_command, patch stage, and attestation all read
    from that path. If you skip it, provision.commit's strategy.detect()
    will REFUSE to handle the target and the finding will fail loud
    with 'source clone missing at /pw/src/<pkgname>/'.

    VERSION PINNING (STRATEGY mode) — the clone MUST be checked out to
    the AFFECTED version (not HEAD), matching the npm/pip install
    version exactly. Inconsistent versions means the source tree does
    not match the installed package, and any patch you write is
    against a tree that does not run. If the initial-message includes
    an "INITIAL SETUP COMMANDS" block below, RUN THOSE FIRST — they
    pin the version consistently in both the git checkout and the
    npm install.

    Do NOT use /tmp/<pkg>/ — that path is not part of the strategy
    convention. Do NOT clone into /pw/src/ directly (must be under a
    subdirectory named after the package).

HTTP REPRODUCER OUTPUT FORMAT (2026-08-10 lesson). For HTTP
reproducers, the parser expects curl -i wire-format output:

    HTTP/1.1 <status> <reason>
    Header: value
    ...
    (blank line)
    <response body>
    #PW_SC <rule_name>=True

USE `curl -sSi <url>` (with the -i flag), NOT curl -sS + your own
"HTTP_STATUS: 200" text. The parser regex only recognizes the real
HTTP status line (starts with HTTP/). Custom labels like
"HTTP_STATUS: 200" or "Status: 200" will parse as status=0
→ classified as harness_fault "no_response" even though the
request succeeded.

DAEMON REPRODUCER RULE (2026-08-10 lesson). If your reproducer
starts a long-running server (dev server, HTTP daemon, DB, etc.) that
must remain up AFTER the reproducer script exits, you MUST use nohup
+ disown so the server survives shell termination:

    nohup <server_cmd> --port <P> > /tmp/<name>.log 2>&1 &
    disown

Reason: patchwing's four_state classifier does its OWN independent
HTTP fetch to your target_url AFTER the reproducer script returns.
If the server was backgrounded with plain '&' and no disown, the
shell exit sends SIGHUP to it, the server dies, and four_state gets
'no_response' → classified as harness_fault. Your reproducer will
have proven the vuln internally (marker printed) but the harness will
report the run as UNCONVINCING.

The rule only applies to server-style targets. One-shot reproducers
(sanitizer runs, file-write triggers, single-fetch HTTP) don't need
this — they don't leave anything running past the script.

ECOSYSTEM STRATEGY. If the finding has an ecosystem (npm, pip, ...),
a strategy owns the build/install shape. Its build_command runs under
network=none at verify — your provision_prep_commands must warm every
cache the build needs. Provision will run a hermeticity smoke build
(network=none) before committing; if that smoke fails, provision
blocks with an actionable error naming which cache is missing."""


def build_initial_msg(finding, draft_http: dict, base_image: str,
                      reference_patch: str = "") -> str:
    """The first user message the provision model sees. Carries the
    finding metadata, base image, operator-authored evidence rules, and
    the upstream reference fix (if any — for CVE findings that already
    localized against an upstream commit)."""
    lines = [
        f"# Provision target for finding {finding.id}",
        "",
        f"**Source**: {finding.source_ref}",
        f"**Title**: {finding.title}",
        f"**Description**:",
        (finding.description or "").strip(),
        "",
        f"## Environment",
        f"- base_image: {base_image}",
        f"- pod is already running; tools operate against it directly",
        "",
        "## Operator-authored HTTP evidence rules",
        "You must bring the target to a state where firing the reproducer",
        "produces a response matching THESE rules. Any deviation reads as",
        "a different bug or a harness fault at reproduce time.",
        "",
        "```json",
        json.dumps(draft_http, indent=2, sort_keys=True),
        "```",
        "",
        "## Emission examples for THIS finding",
        "For each rule above, your reproduce_command must emit ONE line",
        "matching the rule NAME + PATTERN below. Use the #PW_SC canonical",
        "form. The classifier refuses GREEN if a declared rule produced no",
        "reading at all (silent absence != affirmative absence of the bug).",
        "",
    ]
    for _r in (draft_http.get("evidence_rules") or []):
        _n = _r.get("name", "?")
        _pat = _r.get("pattern", "?")
        _k = _r.get("kind", "?")
        if _k == "side_channel_flag":
            lines += [
                f"- rule `{_n}` kind=side_channel_flag pattern={_pat!r}",
                f"    RED   emission: `#PW_SC {_n}={_pat}`",
                f"    GREEN emission: `#PW_SC {_n}=False`  (or any non-{_pat!r} value)",
                f"    ABSENT (never emitted) => HARNESS_FAULT",
            ]
        elif _k in ("side_channel_regex", "response_body_regex", "response_header_regex"):
            _kind_ev = _k.replace("_regex", "")
            lines += [
                f"- rule `{_n}` kind={_k} pattern={_pat!r} (regex)",
                f"    RED  when the pattern appears in the {_kind_ev} evidence",
                f"    GREEN when the {_kind_ev} evidence exists and the pattern does NOT match",
                f"    ABSENT (no evidence source at all) => HARNESS_FAULT",
            ]
    lines += [""]
    # Chunk (setup): if an ecosystem strategy is registered AND it can
    # produce concrete initial-setup commands (git clone + checkout at
    # pinned version + npm install), inject them so GLM's first action
    # is to run these — not to explore-and-improvise the source clone.
    try:
        from . import ecosystems as _ecos
        _eco_name = str((finding.__dict__.get("_ecosystem") if hasattr(finding, "__dict__") else None) or "").strip().lower()
    except Exception:
        _eco_name = ""
    _setup_cmds: list[str] = []
    if _eco_name:
        try:
            _strat = _ecos.for_ecosystem(_eco_name)
            _pkg = str((finding.__dict__.get("_package") if hasattr(finding, "__dict__") else None) or "").strip()
            _fixed = str((finding.__dict__.get("_fixed_version") if hasattr(finding, "__dict__") else None) or "").strip()
            _install_root = f"/pw/{_pkg}-app"
            _cmds = _strat.initial_setup_commands(
                finding.repo_url, _pkg, _install_root, _fixed)
            if _cmds:
                _setup_cmds = list(_cmds)
        except Exception:
            _setup_cmds = []
    # 2026-08-10: emit explicit MODE banner so GLM knows whether it's
    # template mode (paths from template docs) or strategy mode (clone
    # source to /pw/src/<pkg>/). Deterministic from spec — no per-target
    # hardcoding, no LLM guesswork about which convention applies.
    _preferred_template = str((draft_http or {}).get("preferred_template") or "").strip()
    if _preferred_template:
        lines += [
            "## MODE: TEMPLATE",
            f"This finding uses a template pod: `{_preferred_template}`.",
            "The pod is pre-provisioned with the target installed at",
            "the paths documented by that template. Use the endpoint/url",
            "from the http block below as ground truth for where the target",
            "listens. Do NOT clone source under `/pw/src/` — the source",
            "and install paths belong to the template's layout, not the",
            "ecosystem-strategy convention.",
            "",
            "For file-system paths (e.g. localization files, extract",
            "targets), read the paths from the template's docs OR from",
            "wherever the target's dependency manager (npm/pip) installs",
            "them inside the template. Do NOT guess a convention.",
            "",
        ]
    else:
        lines += [
            "## MODE: ECOSYSTEM STRATEGY",
            "This finding uses the ecosystem-strategy provision path.",
            "Clone the target's source to `/pw/src/<pkgname>/` at the",
            "affected version — the initial setup commands below (if any)",
            "give you the exact commands. The patch stage reads source",
            "files relative to that clone.",
            "",
        ]

    # Bootstrap (2026-08-09) runs these deterministically via sb.run()
    # BEFORE this message reaches the model. Surface a short note instead
    # of the fenced block — model should assume tools + clone + install
    # are already done and go straight to authoring the reproducer.
    if _setup_cmds:
        lines += [
            "## POD IS PRE-BOOTSTRAPPED",
            f"Your pod already has: git, curl, jq, python3, node+npm at",
            f"the major matching this target's engines.node, "
            f"pnpm/yarn if the source uses either. Source is cloned at",
            f"`/pw/src/{_pkg}` checked out at the AFFECTED version. Target",
            f"vulnerable package is installed at `{_install_root}`. "
            f"Workspace dependencies for the source tree are also installed.",
            "",
            "Go straight to authoring: (1) start the target, (2) verify it",
            "responds to the endpoint from the http block, (3) prove the",
            "vulnerability, (4) write the reproducer script to /reproduce.pw.sh",
            "that outputs `#PW_SC <rule_name>=True` on success, (5) return",
            "done:true with `target_url`, `reproduce_command`, `install_root`.",
            "",
            "OMITTED — bootstrap already ran these:",
            "```bash",
            "The ecosystem strategy has derived version-pinned setup",
            f"commands for `{_eco_name}` package `{_pkg}` at affected",
            f"version derived from fixed_version={_fixed!r}. Run them",
            "before authoring the reproducer. If any command fails,",
            "STOP and report — the version may not be tagged in git,",
            "or the install may not resolve. Do not improvise past a",
            "failure; version-mismatch between clone and install is",
            "the most common way to get a green verdict on a tree",
            "that isn\'t what runs.",
            "",
            "```bash",
        ] + list(_setup_cmds) + [
            "```",
            "",
            f"install_root: `{_install_root}`  (the path node_modules and",
            "the target's live process load from — you MUST populate this,",
            "and its dist tree is what verify hashes for the sanity check)",
            "",
        ]
    if reference_patch:
        lines += [
            "## Upstream reference fix (context — DO NOT apply, we want the",
            "vulnerable version. The parent commit of this diff is what the",
            "target needs to be built at):",
            "",
            "```diff",
            reference_patch[:8000],
            "```",
        ]
    lines += [
        "",
        "Begin. Return JSON — either tool_calls to explore/install/build,",
        "or the done terminator when the target is up and the reproducer",
        "confirms an evidence match.",
    ]
    return "\n".join(lines)


# --- the loop ------------------------------------------------------------

def derive_node_major(engines_node: str) -> int:
    """LTS-preferred node major from a package.json engines.node string.

    Absent/unparseable → 20 (current LTS). Ecosystem-agnostic — the input
    is the raw engines.node value, whatever the target published.

    Rules (in order):
      1. Extract integer majors 10-30 from the string.
      2. If the string has an open-ended upper bound (`>=` or a single
         `>` / `~=` / just a bare `N`) → prefer the highest LTS at or
         above the declared lower bound.
      3. Otherwise (`^X.Y.Z`, `~X.Y.Z`, or an OR-list of pinned majors)
         → prefer an LTS that is IN the extracted set; else the highest
         extracted major.
      4. Anything else → 20.
    """
    if not engines_node:
        return 20
    import re as _re
    s = str(engines_node)
    majors = sorted({int(m) for m in _re.findall(r'\b(\d+)\b', s)
                     if 10 <= int(m) <= 30})
    if not majors:
        return 20
    LTS = (20, 22, 18)  # preference order
    # Detect open-ended upper: `>=N`, `>N`, or bare `Ns/N` with no `^`/`~`/`||`.
    has_ge = ">=" in s or (">" in s and not "<" in s)
    is_bare = ("^" not in s and "~" not in s and "||" not in s and
                "<" not in s and len(majors) == 1)
    if has_ge or is_bare:
        lower = min(majors)
        for lts in LTS:
            if lts >= lower:
                return lts
        return max(majors)
    # Bounded ranges → prefer LTS that appears in the set
    for lts in LTS:
        if lts in majors:
            return lts
    return max(majors)


def bootstrap_setup(ctx, f, sb, strategy, pkg_name: str,
                     install_root: str, repo_url: str,
                     affected_ref: str) -> None:
    """Deterministic pod preparation BEFORE the first model turn.

    Runs via sb.run() (persistent pod). Fails loud with
    ProvisionBootstrapFailed on any non-zero step — the loop refuses to
    proceed to model turns until the target is on ground truth.

    Order:
      1. apt install base tools (git, curl, jq, python3, ca-certificates)
      2. strategy.source_clone_command → clone source at affected tag
      3. read /pw/src/<pkg>/package.json engines.node
      4. derive_node_major → install nodejs from nodesource at that major
      5. strategy.post_node_setup_commands → target install, sanity,
         workspace tool warm, source-tree workspace deps

    Emits bootstrap_step / bootstrap_ok / bootstrap_failed events for
    audit. Every command tail truncated to 800B in event meta."""
    import hashlib as _h

    def _step(name: str, cmd: str, timeout_s: int = 600):
        r = sb.run(cmd, timeout_s=timeout_s)
        tail = ((r.stdout or "") + "\n---STDERR---\n" + (r.stderr or ""))[-1200:]
        ctx.store.emit(
            f.id, "provision", "bootstrap_step",
            f"{name}: exit={r.returncode} bytes={len(r.stdout or '')}",
            meta={"name": name, "exit": r.returncode,
                  "cmd_head": cmd[:400], "tail": tail[:800]})
        if r.returncode != 0:
            ctx.store.emit(f.id, "provision", "bootstrap_failed",
                           f"{name} exited {r.returncode}",
                           meta={"name": name, "exit": r.returncode,
                                  "tail": tail[:1500]})
            raise ProvisionBootstrapFailed(
                f"bootstrap step {name!r} exited {r.returncode}. Tail:\n"
                f"{tail[-1500:]}")
        return r

    # 1. base tools
    _step("apt_base",
          "apt-get update -qq && "
          "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
          "git curl jq python3 ca-certificates 2>&1 | tail -5",
          timeout_s=600)

    # 2. clone (strategy)
    _step("source_clone",
          strategy.source_clone_command(repo_url, pkg_name, affected_ref),
          timeout_s=600)

    # 3. read engines.node
    source_root = strategy.source_root_in_pod(sb)
    engines_cmd = (
        f"python3 -c \"import json; "
        f"d=json.load(open('{source_root}/package.json')); "
        f"e=d.get('engines') or {{}}; "
        f"print(e.get('node') or '')\"")
    r_engines = sb.run(engines_cmd, timeout_s=30)
    engines_node = (r_engines.stdout or "").strip()
    node_major = derive_node_major(engines_node)
    ctx.store.emit(
        f.id, "provision", "bootstrap_node_derive",
        f"engines.node={engines_node!r} → node_major={node_major}",
        meta={"engines_node": engines_node, "node_major": node_major})

    # 4. install node at derived major
    _step("install_node",
          f"curl -fsSL https://deb.nodesource.com/setup_{node_major}.x "
          f"| bash - >/dev/null 2>&1 && "
          f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs "
          f"2>&1 | tail -5 && "
          f"node --version && npm --version",
          timeout_s=600)

    # 5. post-node strategy commands, in order
    for i, cmd in enumerate(strategy.post_node_setup_commands(
            source_root, pkg_name, install_root, affected_ref), start=1):
        _step(f"post_node_{i}", cmd, timeout_s=2400)  # 40min for shamefully-hoist on big monorepos

    ctx.store.emit(f.id, "provision", "bootstrap_ok",
                    "all bootstrap steps completed",
                    meta={"node_major": node_major})


def _append_and_persist_user_msg(ctx, f, convo, content: str,
                                    tag: str, turn: int) -> None:
    """Append a user message to convo AND persist to artifacts so the
    check-failure feedback / nudge messages are grepable after the fact
    instead of vanishing with the process. Zero behavior change to the
    loop — additive."""
    convo.append({"role": "user", "content": content})
    ctx.store.add_artifact(
        f.id, "convo_user_msg", "provision",
        content=content,
        meta={"turn": turn, "tag": tag,
              "content_bytes": len(content)},
        base_commit="", model="")


def run_provision_loop(ctx, f, client, sb, draft_http: dict,
                       base_image: str, reference_patch: str = "",
                       max_turns: int = 40,
                       max_usd: float = 0.0,
                       *,
                       strategy=None,
                       pkg_name: str = "",
                       install_root_hint: str = "",
                       affected_ref: str = "") -> tuple[dict, int, int]:
    """Closed loop for provision.

    Returns (done_obj, turns_used, tool_calls_total). Raises one of the
    three exceptions above on non-terminating exits.

    The tool-dispatch code mirrors the pattern in stages.py:1951-2008
    deliberately — same shape (5 calls max per turn, duplicate-call
    detection, results fed back as a user message) so that the audit
    trail reads the same way for both loops.

    Fix 1c: HTTP-KIND ONLY. Blocks if draft_http.evidence_rules is empty
    (or absent). Under Fix 0's affirmative-negative requirement, running
    provision without rule names guarantees the reproducer emits an
    ad-hoc marker no rule can match — the finding would reject at
    reproduce for a spec/provision communication gap rather than for a
    real reproducer failure. Fail loudly at loop entry instead."""
    _rules_at_entry = (draft_http or {}).get("evidence_rules") or []
    if not _rules_at_entry:
        raise ProvisionInvalidSpec(
            "run_provision_loop: draft_http.evidence_rules is empty. "
            "Provision refuses to run without at least one evidence rule; "
            "post a draft-spec (or target-spec) declaring what marker(s) "
            "the reproducer will emit. See /api/finding/<fid>/draft-spec.")

    # BOOTSTRAP (2026-08-09): deterministic pod prep BEFORE first model turn.
    # Runs base-tool install + source clone + node install (derived major) +
    # target install + workspace-tool warm + source-tree deps. If any step
    # fails, raise ProvisionBootstrapFailed — the loop refuses to start.
    # r3 proved that leaving these to model discretion (fenced code block
    # the model was free to skim) meant step 5 workspace-tool warmer never
    # ran, and the hermetic smoke check burned all 60 turns on a missing
    # command. Now deterministic.
    if strategy is not None:
        _bootstrap_install_root = install_root_hint or f"/pw/{pkg_name}-app"
        bootstrap_setup(ctx, f, sb, strategy, pkg_name,
                         _bootstrap_install_root, f.repo_url, affected_ref)
    convo = [
        {"role": "system", "content": PROVISION_SYSTEM},
        {"role": "user", "content": build_initial_msg(
            f, draft_http, base_image, reference_patch)},
    ]
    # LOOP HARDENING (2026-08-09):
    #   FORCE_RECOMMIT_EVERY = tool_calls between synthetic re-check cycles
    #   NO_PROGRESS_STREAK   = identical check-fail sigs → abort as stuck
    FORCE_RECOMMIT_EVERY = 8
    NO_PROGRESS_STREAK = 3
    FORCE_RECOMMIT_MAX_S = 300         # if first commit >= this, disable
    _tool_calls_since_check = 0        # for force-recommit trigger
    _first_done_seen = False           # gate force-recommit on first done
    _force_recommit_count = 0          # for tag suffix
    _first_commit_elapsed_s = 0.0      # measured at first done commit
    _force_recommit_disabled = False   # set if first commit exceeds threshold
    _fail_sigs: list = []              # (check_name, got, tail_hash)
    seen_calls: dict[tuple, int] = {}
    seen_hosts: set[str] = set()   # for provision_egress_host emit
    tool_calls_total = 0
    _last_failed_results: list = []  # for ProvisionLoopExhausted
    _last_target_url = ""             # for force-recommit re-checks
    _last_reproduce_cmd = ""

    for turn in range(1, max_turns + 1):
        # FORCE-RECOMMIT (2026-08-09): after N tool_calls with no
        # intervening done:true (and post-first-done), synthesize a
        # commit + check cycle so GLM's persistent-pod fixes must reach
        # the image the checks read from. r3 proved the failure mode of
        # NOT doing this: 33 turns of GLM installing pnpm in the live
        # pod while every check stayed against the frozen turn-24 image.
        if (strategy is not None and _first_done_seen and
                not _force_recommit_disabled and
                _tool_calls_since_check >= FORCE_RECOMMIT_EVERY):
            _force_recommit_count += 1
            _image_tag = f"patchwing-provisioned-{f.id}-fr{_force_recommit_count}"
            try:
                _tag_ret, _fr_elapsed = commit_pod(sb, _image_tag)
            except ProvisionCommitFailed as _e:
                ctx.store.emit(f.id, "provision", "force_recommit_failed",
                                f"turn {turn}: {_e}",
                                meta={"turn": turn, "err": str(_e)[:400]})
                # If forced commit failed, don't retry — reset counter but
                # rely on model to re-emit done:true itself.
                _tool_calls_since_check = 0
                _fr_elapsed = None
            else:
                sb.image = _image_tag
                ctx.store.emit(f.id, "provision", "loop_force_recommit",
                                f"turn {turn}: forced commit → {_image_tag} "
                                f"after {FORCE_RECOMMIT_EVERY} tool_calls "
                                f"without done:true",
                                meta={"turn": turn, "image": _image_tag})
                _install_root_for_check = str(
                    (obj_prev := {}).get("install_root")
                    or install_root_hint or f"/pw/{pkg_name}-app")
                from . import provision_checks as _pc
                _fr_results = _pc.run_checks(
                    sb, strategy, pkg_name, _install_root_for_check,
                    affected_ref)
                for _r in _fr_results:
                    ctx.store.emit(
                        f.id, "provision",
                        "check_pass" if _r.ok else "check_fail",
                        f"{_r.name}: {'PASS' if _r.ok else 'FAIL — ' + _r.got[:120]}",
                        meta={"turn": turn, "check": _r.name, "ok": _r.ok,
                              "expected": _r.expected[:400],
                              "got": _r.got[:400],
                              "force_recommit": _force_recommit_count})
                _fr_failed = [_r for _r in _fr_results if not _r.ok]
                if not _fr_failed and _last_target_url and _last_reproduce_cmd:
                    # All checks pass on the force-committed image — terminate.
                    _final_obj = {"done": True,
                                   "target_url": _last_target_url,
                                   "reproduce_command": _last_reproduce_cmd,
                                   "install_root": _install_root_for_check,
                                   "image_tag": _image_tag}
                    ctx.store.emit(
                        f.id, "provision", "loop_done",
                        f"target ready via force-recommit at turn {turn} "
                        f"on {_image_tag}",
                        meta={"turn": turn, "target_url": _last_target_url,
                              "reproduce_command": _last_reproduce_cmd,
                              "image_tag": _image_tag,
                              "install_root": _install_root_for_check,
                              "force_recommit": True})
                    return _final_obj, turn, tool_calls_total
                elif _fr_failed:
                    _fr_msg = ("FORCE-RECOMMIT (turn {t}): committed current "
                                "pod to a fresh image, ran the 3 binary checks. "
                                "{f}/{n} checks failed. Your persistent-pod "
                                "fixes must land in the image the checks "
                                "read from. Either re-emit done:true (loop "
                                "will re-commit + re-check) or wait for the "
                                "next force-recommit in "
                                "{r} more tool_calls.\n\n{body}").format(
                        t=turn, f=len(_fr_failed), n=len(_fr_results),
                        r=FORCE_RECOMMIT_EVERY,
                        body=_pc.format_failures_for_model(_fr_results))
                    _append_and_persist_user_msg(
                        ctx, f, convo, _fr_msg,
                        tag="force_recommit_notice", turn=turn)
                    # Fold into no-progress signature tracking too
                    import hashlib as _hh
                    for _fr in _fr_failed:
                        _sig = (_fr.name, _fr.got.strip(),
                                 _hh.sha256((_fr.tail or "").encode()[-800:]).hexdigest()[:16])
                        _fail_sigs.append(_sig)
                    # Reset counter so next force fires FORCE_RECOMMIT_EVERY calls out
                    _tool_calls_since_check = 0
                    _last_failed_results = _fr_results

        _spent = budget_mod.spent(ctx.store, f.id)
        remaining_usd = None
        remaining_usd_str = "no priced ceiling"
        if max_usd > 0:
            remaining_usd = max(0.0, max_usd - _spent.usd)
            remaining_usd_str = f"${remaining_usd:.2f} of ${max_usd:.2f}"

        if max_usd > 0 and _spent.priced and remaining_usd <= 0:
            raise ProvisionBudgetExhausted(
                f"USD cap reached: spent ${_spent.usd:.4f} against "
                f"${max_usd:.2f} at turn {turn}, "
                f"{tool_calls_total} tool call(s)")

        ctx.store.emit(
            f.id, "provision", "loop_turn",
            f"turn {turn}/{max_turns}, convo="
            f"{sum(len(m['content']) for m in convo)}B, "
            f"remaining: {remaining_usd_str}",
            meta={"turn": turn, "max_turns": max_turns,
                  "convo_bytes": sum(len(m["content"]) for m in convo),
                  "convo_messages": len(convo),
                  "remaining_usd": remaining_usd,
                  "spent_usd": _spent.usd})

        obj = client.chat_json(convo, required=())
        ctx.store.add_artifact(
            f.id, "response", "provision",
            content=(getattr(client, "last_raw_response", "") or ""),
            meta={"seat": "provision",
                  "model": getattr(client.cfg, "model", "?"),
                  "endpoint": getattr(client.cfg, "endpoint", ""),
                  "turn": turn,
                  "attempt": f"provision_turn_{turn}"},
            model=getattr(client.cfg, "model", ""))

        # THROWAWAY diagnostic — on turn 1, log the raw response object
        # + first-call shape to the event log so if the normalizer misses
        # a shape variant we didn't anticipate, we see it immediately in
        # the trace. Remove after Struts provision lands successfully.
        if turn == 1:
            raw = getattr(client, "last_raw_response", "") or ""
            first_call_shape = None
            if (isinstance(obj, dict)
                    and isinstance(obj.get("tool_calls"), list)
                    and obj["tool_calls"]):
                first_call_shape = json.dumps(obj["tool_calls"][0])[:800]
            ctx.store.emit(
                f.id, "provision", "provision_raw_response_turn1",
                f"turn 1 raw response ({len(raw)}B), "
                f"top-level keys={list(obj.keys()) if isinstance(obj, dict) else '?'}",
                meta={"turn": 1, "raw_head": raw[:2000],
                      "top_keys": list(obj.keys()) if isinstance(obj, dict) else [],
                      "first_call_shape": first_call_shape})

        if isinstance(obj, dict) and obj.get("give_up"):
            raise ProvisionGaveUp(str(obj.get("give_up"))[:400])

        # DONE terminator
        if isinstance(obj, dict) and obj.get("done") is True:
            target_url = str(obj.get("target_url") or "").strip()
            reproduce_cmd = str(obj.get("reproduce_command") or "").strip()
            if not target_url or not reproduce_cmd:
                # Feed back — do NOT accept an incomplete done
                missing = []
                if not target_url: missing.append("target_url")
                if not reproduce_cmd: missing.append("reproduce_command")
                convo.append(
                    {"role": "assistant",
                     "content": json.dumps(obj)[:2000]})
                convo.append(
                    {"role": "user",
                     "content": (f"You returned done:true but missing "
                                 f"{', '.join(missing)}. Provide both, "
                                 f"then return the done terminator again.")})
                continue
            # RECURSIVE PROVISION LOOP (2026-08-08 / hardened 2026-08-09).
            # done:true is a CHECK TRIGGER, not a terminator. Commit the
            # current pod → run 3 binary checks against that image → all
            # pass = terminate, any fail = feed back and continue.
            #
            # 2026-08-09: also stash target_url + reproduce_command so a
            # force-recommit later has something to declare, and gate the
            # force-recommit trigger on having seen at least one done.
            _first_done_seen = True
            _last_target_url = target_url
            _last_reproduce_cmd = reproduce_cmd
            _tool_calls_since_check = 0

            # No strategy → no checks (ARVO / non-ecosystem findings). Legacy
            # single-shot success semantics preserved for that case.
            if strategy is None:
                ctx.store.emit(
                    f.id, "provision", "loop_done",
                    f"target ready at {target_url} in {turn} turn(s) "
                    f"(no strategy — checks skipped)",
                    meta={"turn": turn, "target_url": target_url,
                          "reproduce_command": reproduce_cmd,
                          "tool_calls_total": tool_calls_total})
                return obj, turn, tool_calls_total

            # Ecosystem-strategy path — checks required.
            install_root = str(obj.get("install_root") or install_root_hint
                                 or "").strip()
            if not install_root:
                # done:true without install_root — impossible to check.
                convo.append({"role": "assistant",
                              "content": json.dumps(obj)[:2000]})
                convo.append({"role": "user",
                              "content": ("You returned done:true but "
                                          "install_root is empty — the "
                                          "loop requires it for the "
                                          "ecosystem strategy checks. "
                                          "Include install_root in your "
                                          "done object.")})
                continue

            image_tag = f"patchwing-provisioned-{f.id}"
            # commit_pod raises ProvisionCommitFailed on error/timeout
            # (its own bucket, NOT model give-up). Elapsed drives adaptive
            # force-recommit decision below.
            _image_tag_ret, _commit_elapsed = commit_pod(sb, image_tag)
            if _first_commit_elapsed_s == 0.0:
                _first_commit_elapsed_s = _commit_elapsed
                ctx.store.emit(
                    f.id, "provision", "loop_commit_timed",
                    f"first real commit: {_commit_elapsed:.1f}s "
                    f"(threshold for force-recommit disable: "
                    f"{FORCE_RECOMMIT_MAX_S}s)",
                    meta={"turn": turn,
                          "commit_elapsed_s": round(_commit_elapsed, 2),
                          "threshold_s": FORCE_RECOMMIT_MAX_S})
                if _commit_elapsed >= FORCE_RECOMMIT_MAX_S:
                    _force_recommit_disabled = True
                    ctx.store.emit(
                        f.id, "provision", "force_recommit_disabled_cost",
                        f"first commit {_commit_elapsed:.0f}s >= "
                        f"{FORCE_RECOMMIT_MAX_S}s — disabling force-recommit "
                        f"for rest of finding (relying on model self-correct)",
                        meta={"commit_elapsed_s": round(_commit_elapsed, 2),
                              "threshold_s": FORCE_RECOMMIT_MAX_S})
            # Update sandbox image so run_ephemeral spawns from the fresh
            # commit (includes GLM's apt-get / npm install / clone work).
            sb.image = image_tag
            ctx.store.emit(
                f.id, "provision", "loop_commit",
                f"committed pod to {image_tag} at turn {turn} "
                f"(pre-check)",
                meta={"turn": turn, "image": image_tag})

            # Run the three binary checks.
            from . import provision_checks as _pc
            results = _pc.run_checks(sb, strategy, pkg_name, install_root,
                                       affected_ref)
            for r in results:
                ctx.store.emit(
                    f.id, "provision",
                    "check_pass" if r.ok else "check_fail",
                    f"{r.name}: {'PASS' if r.ok else 'FAIL — ' + (r.got[:120])}",
                    meta={"turn": turn, "check": r.name, "ok": r.ok,
                          "expected": r.expected[:400],
                          "got": r.got[:400]})
            _failed = [r for r in results if not r.ok]
            if not _failed:
                # ALL CHECKS PASSED — commit is the final image, we're done.
                obj["image_tag"] = image_tag
                obj["install_root"] = install_root
                ctx.store.emit(
                    f.id, "provision", "loop_done",
                    f"target ready at {target_url} in {turn} turn(s) "
                    f"— all {len(results)} checks passed on {image_tag}",
                    meta={"turn": turn, "target_url": target_url,
                          "reproduce_command": reproduce_cmd,
                          "tool_calls_total": tool_calls_total,
                          "image_tag": image_tag,
                          "install_root": install_root})
                return obj, turn, tool_calls_total

            # 1+ check failed — feed back and continue
            convo.append({"role": "assistant",
                          "content": json.dumps(obj)[:2000]})
            _feedback_msg = _pc.format_failures_for_model(results)
            _append_and_persist_user_msg(
                ctx, f, convo, _feedback_msg,
                tag="check_failure_feedback", turn=turn)
            # No-progress guard: signature = (name, exit_code_from_got, tail_hash).
            # Only compares among check_fails of the SAME check_name; a
            # smoke→ref-mismatch swap is progress, not repetition.
            import hashlib as _h
            _fails = [r for r in results if not r.ok]
            for _fr in _fails:
                _sig = (_fr.name,
                        _fr.got.strip(),
                        _h.sha256((_fr.tail or "").encode()[-800:]).hexdigest()[:16])
                _fail_sigs.append(_sig)
            _tail_by_check: dict = {}
            for _s in _fail_sigs:
                _tail_by_check.setdefault(_s[0], []).append(_s)
            for _name, _seq in _tail_by_check.items():
                _last = _seq[-NO_PROGRESS_STREAK:]
                if len(_last) >= NO_PROGRESS_STREAK and \
                        all(s == _last[0] for s in _last):
                    ctx.store.emit(
                        f.id, "provision", "loop_stuck",
                        f"check {_name!r} failed {NO_PROGRESS_STREAK}x "
                        f"with identical signature — aborting",
                        meta={"check": _name, "sig": _last[0]})
                    raise ProvisionLoopStuck(
                        f"Check {_name!r} failed {NO_PROGRESS_STREAK} "
                        f"consecutive times with identical signature "
                        f"(exit={_last[0][1]}, tail_hash={_last[0][2]}). "
                        f"Definition-of-insanity abort. Last tail:\n"
                        f"{_fails[-1].tail[-1500:]}")
            _last_failed_results = results
            _tool_calls_since_check = 0  # reset after check round
            continue

        # TOOL_CALLS
        calls = obj.get("tool_calls") if isinstance(obj, dict) else None
        # Accept a bare single-call at the top level as a 1-element
        # list. Kimi sometimes emits {"tool":"exec_in_pod","args":{...}}
        # (or the OpenAI {"function":{...}} shape) WITHOUT the outer
        # {"tool_calls":[...]} wrapper — this run burned 40 turns
        # before the fix because the nudge didn't teach the wrapper.
        if (not calls) and isinstance(obj, dict) \
                and ("tool" in obj or "function" in obj):
            calls = [obj]
        if not isinstance(calls, list) or not calls:
            # Model returned neither tool_calls nor done — nudge and continue
            convo.append(
                {"role": "assistant",
                 "content": json.dumps(obj)[:2000] if isinstance(obj, dict)
                            else str(obj)[:2000]})
            convo.append(
                {"role": "user",
                 "content": ('That response used neither tool_calls nor the '
                             'done terminator. Either call more tools to '
                             'explore/install/build, or return '
                             '{"done": true, "target_url": "...", '
                             '"reproduce_command": "..."} when the target '
                             'is up and http_probe confirms an evidence '
                             'match. Do not mix them.')})
            continue

        results = []
        for call in calls[:5]:
            # Normalize BEFORE any dispatch — accepts legacy {tool,args}
            # AND OpenAI {function:{name,arguments}} shapes. See
            # _normalize_tool_call for the Kimi-hit motivating this.
            call = _normalize_tool_call(call)
            if not isinstance(call, dict):
                results.append({"tool": "?", "args": {},
                                "error": "tool_call must be a dict"})
                continue
            tool_name = str(call.get("tool", ""))
            args = call.get("args", {}) or {}
            if not isinstance(args, dict):
                args = {}

            key = (tool_name, json.dumps(args, sort_keys=True))
            if key in seen_calls:
                prior = seen_calls[key]
                ctx.store.emit(
                    f.id, "provision", "loop_duplicate_call",
                    f"{tool_name} duplicated from turn {prior}",
                    meta={"turn": turn, "tool": tool_name, "args": args,
                          "prior_turn": prior})
                results.append({
                    "tool": tool_name, "args": args,
                    "error": (f"duplicate call — you already ran "
                              f"{tool_name}({args}) at turn {prior}; if "
                              f"you need the fresh output, change something "
                              f"first (state, args, or take a different "
                              f"approach)")})
                continue
            seen_calls[key] = turn
            tool_calls_total += 1
            _tool_calls_since_check += 1

            fn = PROVISION_TOOLS.get(tool_name)
            if fn is None:
                err = (f"unknown tool {tool_name!r}; available: "
                       f"{list(PROVISION_TOOLS)}")
                ctx.store.emit(
                    f.id, "provision", "loop_tool_result",
                    f"{tool_name} ERROR: {err[:80]}",
                    meta={"turn": turn, "tool": tool_name, "error": err})
                results.append({"tool": tool_name, "args": args,
                                "error": err})
                continue
            ctx.store.emit(
                f.id, "provision", "loop_tool_call",
                f"{tool_name}({json.dumps(args)[:120]})",
                meta={"turn": turn, "tool": tool_name, "args": args})
            # Diagnostic: emit one provision_egress_host per unique host
            # touched. exec_in_pod cmds carry curl/wget/git URLs;
            # install_package name and http_probe url are direct signals.
            _cmd_str = ""
            if tool_name == "exec_in_pod":
                _cmd_str = str(args.get("cmd", ""))
            elif tool_name == "http_probe":
                _cmd_str = str(args.get("url", ""))
            fresh_hosts = _extract_hosts_from_cmd(_cmd_str) - seen_hosts
            for host in sorted(fresh_hosts):
                seen_hosts.add(host)
                ctx.store.emit(
                    f.id, "provision", "provision_egress_host",
                    f"first touch of host {host}",
                    meta={"turn": turn, "host": host, "tool": tool_name,
                          "source": "cmd_regex"})
            try:
                out = fn(sb, **args)
                ctx.store.emit(
                    f.id, "provision", "loop_tool_result",
                    f"{tool_name} -> {len(out)}B",
                    meta={"turn": turn, "tool": tool_name,
                          "output_bytes": len(out)})
                results.append({"tool": tool_name, "args": args,
                                "output": out})
            except (ToolError, TypeError, KeyError) as e:
                err = str(e)
                ctx.store.emit(
                    f.id, "provision", "loop_tool_result",
                    f"{tool_name} ERROR: {err[:80]}",
                    meta={"turn": turn, "tool": tool_name,
                          "error": err[:400]})
                results.append({"tool": tool_name, "args": args,
                                "error": err})

        # Feed tool results back
        chunks = []
        for r in results:
            head = f"### {r['tool']}({json.dumps(r.get('args', {}))})"
            if "error" in r:
                chunks.append(f"{head}\n\nERROR: {r['error']}")
            else:
                chunks.append(f"{head}\n\n{r['output']}")
        remaining_turns = max_turns - turn
        footer = (f"\n\n[budget: {remaining_turns} turn(s) left of "
                  f"{max_turns}, {remaining_usd_str}]")
        convo.append({"role": "assistant",
                      "content": json.dumps(obj)[:4000]})
        convo.append({"role": "user",
                      "content": "\n\n".join(chunks) + footer})

    # Include the last failing check tail so the finding's error column
    # shows WHY the loop exhausted (not just that it did).
    _tail_msg = ""
    if _last_failed_results:
        _blocks = [r.as_prompt_block() for r in _last_failed_results if not r.ok]
        if _blocks:
            _tail_msg = "\n\nLAST CHECK FAILURE(s):\n" + "\n\n".join(_blocks)
    raise ProvisionLoopExhausted(
        f"provision loop exhausted max_turns={max_turns} "
        f"({tool_calls_total} tool call(s), no all-checks-pass done)" + _tail_msg)


# --- pod commit + recipe extraction --------------------------------------

# --- preferred_template resolution (Pass 5) ------------------------------
# Called from @stage("provision") BEFORE the pod is created. Resolves a
# template name from spec.http.preferred_template into an image tag,
# gating on: (a) the template row exists, (b) podman still has the image
# under that tag, (c) the current digest matches what was recorded at
# build time. Any of the three fails → hard fail, no silent fallback.
# Silent fallback would let a drifted template ship a different
# environment than the one that was verified — the whole point of the
# digest field is to detect that.

def _podman_image_exists(backend: str, tag: str) -> bool:
    """True if podman/docker has an image at `tag`. `podman image
    exists` returns exit 0 if present, exit 1 if not — distinct from
    other inspect failure modes (auth, transport, disk)."""
    try:
        r = subprocess.run(
            [backend, "image", "exists", tag],
            capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return r.returncode == 0


def resolve_template_image(*, store, sandbox_config,
                           template_name: str) -> dict:
    """Resolve spec.http.preferred_template to a verified image tag.

    Returns one of:
      {"ok": True,
       "image_tag": "patchwing-template:<name>",
       "verified_digest": "sha256:...",
       "template_name": "<name>"}
      {"ok": False, "outcome": "provision_template_missing", "error": "..."}
      {"ok": False, "outcome": "provision_template_image_gone", "error": "..."}
      {"ok": False, "outcome": "provision_template_digest_drift", "error": "..."}

    Three gates, three distinct outcomes:
      1. Row exists in pod_templates
      2. Image exists under the tag in podman's local registry
      3. Podman's current digest == pod_templates.image_digest

    NEVER falls back to bare ubuntu on failure — a drifted template
    would ship an unverified environment.
    """
    from . import template_builder as tb_mod

    # Gate 1 — template row must still exist
    tpl = store.get_template((template_name or "").strip())
    if tpl is None:
        return {"ok": False,
                "outcome": "provision_template_missing",
                "error": (f"preferred_template {template_name!r} refers to "
                          f"a pod_templates row that no longer exists — "
                          f"pick another from /templates or rebuild it")}

    tag = tpl.image_tag
    backend = getattr(sandbox_config, "backend", "podman") or "podman"

    # Gate 2 — podman must have the image under that tag
    if not _podman_image_exists(backend, tag):
        return {"ok": False,
                "outcome": "provision_template_image_gone",
                "error": (f"template {tpl.name!r} exists in pod_templates "
                          f"but podman has no image at {tag!r} — the tag "
                          f"was removed from the registry (maybe by "
                          f"`podman rmi` for disk space). Rebuild the "
                          f"template.")}

    # Gate 3 — digest must match what was recorded at build time
    try:
        current_digest = tb_mod._image_digest(backend, tag)
    except tb_mod.BuildFailed as e:
        return {"ok": False,
                "outcome": "provision_template_image_gone",
                "error": (f"template {tpl.name!r}: cannot read current "
                          f"digest for {tag!r} — {e}")}

    if (tpl.image_digest or "").strip() != current_digest.strip():
        return {"ok": False,
                "outcome": "provision_template_digest_drift",
                "error": (f"template {tpl.name!r} DIGEST DRIFT: "
                          f"pod_templates recorded {tpl.image_digest[:19]}… "
                          f"at build time, podman now reports "
                          f"{current_digest[:19]}… for tag {tag!r}. Tags "
                          f"are mutable, digests are not — a different "
                          f"image is now sitting behind this tag, and "
                          f"attaching would give provision an environment "
                          f"that was never verified. Rebuild the template "
                          f"or investigate what re-tagged the image.")}

    return {"ok": True,
            "image_tag": tag,
            "verified_digest": current_digest,
            "template_name": tpl.name}




def materialize_reproducer(sb, done_obj: dict) -> tuple[str, list[str]]:
    """Given provision's `done_obj` (which must carry `reproducer_script`
    bytes + optional `reproducer_extra_files`), write /reproduce.pw.sh in
    the pod, plus each extra file to its declared path, and return
    (canonical_reproduce_command, list_of_files_to_freeze).

    Called from stages.py provision commit block. Fails loud (raises)
    if bytes are missing/empty or if any file cannot be written. The
    caller catches and converts to StageResult.fail with a specific
    outcome tag."""
    script = done_obj.get("reproducer_script")
    if not isinstance(script, str) or not script.strip():
        raise ValueError(
            "provision done_obj missing `reproducer_script` (script bytes). "
            "See PROVISION_SYSTEM REPRODUCER CONTRACT.")
    canonical_path = "/reproduce.pw.sh"
    sb.write(canonical_path, script)
    sb.run(f"chmod +x {canonical_path}")
    frozen = [canonical_path]
    extras = done_obj.get("reproducer_extra_files") or []
    if extras and not isinstance(extras, list):
        raise ValueError(
            "reproducer_extra_files must be a list of {path, bytes} objects")
    for i, e in enumerate(extras):
        if not isinstance(e, dict):
            raise ValueError(f"reproducer_extra_files[{i}] must be an object")
        p = e.get("path")
        b = e.get("bytes")
        if not (isinstance(p, str) and p.startswith("/") and
                isinstance(b, str) and b):
            raise ValueError(
                f"reproducer_extra_files[{i}] requires absolute-path `path` "
                f"and non-empty string `bytes`; got path={p!r}")
        # Ensure parent dir
        parent = p.rsplit("/", 1)[0] or "/"
        if parent and parent != "/":
            sb.run(f"mkdir -p {parent}")
        sb.write(p, b)
        frozen.append(p)
    return "bash " + canonical_path, frozen

# Commit-timeout derivation (2026-08-09): rootless podman + fuse-overlayfs
# on Ubuntu 24.04 is dominated by userspace file-by-file diff; kernel
# native overlay is blocked by unprivileged_userns AppArmor profile that
# we chose to keep enabled. Real throughput measured on this VM: ~30 MB/s
# for `podman commit` regardless of pod size (dominated by fs walk, not
# tarball write). Formula gives 2x buffer over that measured rate.
COMMIT_MBPS = 30
COMMIT_TIMEOUT_MIN_S = 300         # floor — cover the 33s bare-ubuntu baseline
COMMIT_TIMEOUT_MAX_S = 7200        # ceiling — 2h absolute cap


def _commit_derive_timeout(sb) -> int:
    """Return a size-derived commit timeout in seconds. Reads the pod's
    read-write layer size via `podman container inspect .SizeRw` (cheap,
    no full du). Falls back to the max cap if inspect fails.

    Formula: max(MIN, size_MB / MBPS * 2), capped at MAX."""
    backend = getattr(sb, "backend", "podman")
    cid = getattr(sb, "cid", "") or ""
    if not cid:
        return COMMIT_TIMEOUT_MAX_S
    try:
        r = subprocess.run(
            [backend, "container", "inspect", cid,
             "--format", "{{.SizeRw}}"],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return COMMIT_TIMEOUT_MAX_S
        size_bytes = int((r.stdout or "0").strip() or 0)
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return COMMIT_TIMEOUT_MAX_S
    size_mb = size_bytes / (1024 * 1024)
    derived = int(size_mb / COMMIT_MBPS * 2)
    return max(COMMIT_TIMEOUT_MIN_S, min(COMMIT_TIMEOUT_MAX_S, derived))


def commit_pod(sb, image_tag: str, timeout_s: int | None = None
                ) -> tuple[str, float]:
    """Commit the running pod to a new image tag. Returns (tag, elapsed_s).

    Uses whatever container backend the sandbox exposes via sb.backend
    (podman/docker). Raises ProvisionCommitFailed on failure OR timeout —
    the caller should NOT wrap this in ProvisionGaveUp; the outcome bucket
    is `provision_commit_failed`.

    `timeout_s` — if None, derived from the pod's read-write layer size
    (see _commit_derive_timeout). Explicit override for callers that know
    a smaller/larger bound.
    """
    import time as _t
    backend = getattr(sb, "backend", "podman")
    cid = getattr(sb, "cid", "") or ""
    if not cid:
        raise ProvisionCommitFailed(
            "commit_pod: sandbox has no cid — pod not running")
    t_effective = int(timeout_s) if timeout_s else _commit_derive_timeout(sb)
    t0 = _t.time()
    try:
        r = subprocess.run(
            [backend, "commit", cid, image_tag],
            capture_output=True, text=True, timeout=t_effective)
    except subprocess.TimeoutExpired as e:
        raise ProvisionCommitFailed(
            f"commit_pod: {backend} commit timed out after {t_effective}s "
            f"on {cid} → {image_tag}. Pod rw-layer size may exceed the "
            f"derived timeout budget (COMMIT_MBPS={COMMIT_MBPS}). "
            f"Root cause on this VM: userspace overlay diff.")
    except FileNotFoundError as e:
        raise ProvisionCommitFailed(f"commit_pod: {backend} not found: {e}")
    elapsed = _t.time() - t0
    if r.returncode != 0:
        raise ProvisionCommitFailed(
            f"commit_pod: {backend} commit exit {r.returncode} after "
            f"{elapsed:.1f}s: {(r.stderr or '').strip()[:400]}")
    return image_tag, elapsed


def recipe_from_events(ctx, finding) -> list:
    """Walk the finding's event log for provision loop_tool_call events
    and return the ordered list of successful calls — the audit trail's
    'what did provision actually do' for the spec's provision_recipe
    field."""
    recipe: list = []
    try:
        rows = ctx.store.conn.execute(
            "SELECT kind, meta, created_at FROM events "
            "WHERE finding_id = ? AND stage = 'provision' "
            "ORDER BY id ASC", (finding.id,)).fetchall()
    except Exception:
        return recipe
    for row in rows:
        if row["kind"] != "loop_tool_call":
            continue
        try:
            m = json.loads(row["meta"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        recipe.append({
            "tool": m.get("tool", "?"),
            "args": m.get("args", {}),
            "turn": m.get("turn"),
            "ts": row["created_at"],
        })
    return recipe
