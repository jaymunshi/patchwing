"""Investigation tools for the patch stage.

The one-shot patch stage assumes the fix belongs in the files the crash trace
names. That assumption breaks when the surface (where the sanitizer fires) is
downstream from the underlying defect (where the wrong logic lives): MSan
reports an uninitialized read where the parser reads, origin frames name the
allocation site, but the actual bug may be a SAX handler that leaks a
partially-initialized node into that buffer.

These tools let the model investigate rather than pattern-match: read source
files it wasn't given, grep for patterns, list directories, resolve function
names by name. The model decides what to look at based on the trace and its
evolving hypothesis. PatchWing runs the tools in the pod and appends the
results to the conversation; the model is still the decider.
"""

from __future__ import annotations

import re
import shlex

from .sandbox import SandboxError


class ToolError(Exception):
    """A tool call could not be executed. Fed back to the model as an error
    result so it can adjust the next call; not a stage-terminating failure."""


def _clip(text: str, max_bytes: int, kind: str) -> str:
    if len(text) <= max_bytes:
        return text
    return (text[:max_bytes]
            + f"\n\n[... truncated at {max_bytes} bytes; full {kind} was "
              f"{len(text)} bytes]")


def read_file(sb, path: str, max_bytes: int = 200000) -> str:
    try:
        body = sb.read(path)
    except SandboxError as e:
        raise ToolError(f"read_file({path!r}): {e}")
    return _clip(body, max_bytes, "file")


def list_dir(sb, path: str) -> str:
    r = sb.run(f"ls -la {shlex.quote(path)}")
    if r.returncode != 0:
        raise ToolError(f"list_dir({path!r}): "
                        f"{(r.stderr or 'no such directory').strip()[:200]}")
    return _clip(r.stdout, 20000, "listing")


def grep(sb, pattern: str, path_glob: str = "*.c",
         root: str = ".", max_lines: int = 200) -> str:
    cmd = (f"grep -rn --include={shlex.quote(path_glob)} -- "
           f"{shlex.quote(pattern)} {shlex.quote(root)}")
    r = sb.run(cmd)
    # grep exits 1 on no-match; that's data, not an error
    if r.returncode not in (0, 1):
        raise ToolError(f"grep({pattern!r}, {path_glob!r}): "
                        f"{r.stderr.strip()[:200]}")
    lines = r.stdout.splitlines()
    if not lines:
        return "(no matches)"
    if len(lines) > max_lines:
        head = "\n".join(lines[:max_lines])
        return (head
                + f"\n\n[... {len(lines) - max_lines} more matches "
                  "truncated; narrow the pattern or path_glob]")
    return r.stdout


_DEF_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_ *]*\b\w+\s*\(")


def show_function(sb, name: str, root: str = ".") -> str:
    """Locate a C function's definition by name and return its body.

    Uses grep to find lines that look like a definition (identifier + open
    paren at a plausible column), reads the enclosing file, walks braces to
    the closing `}`. Returns up to 3 candidates so the model can pick.
    """
    # Match `name(` on any line — prototypes and definitions both surface;
    # the brace walk filters non-definitions naturally (no `{` follows a `;`).
    pat = rf"\b{re.escape(name)}\s*\("
    cmd = (f"grep -Enrn --include=*.c --include=*.h -- "
           f"{shlex.quote(pat)} {shlex.quote(root)}")
    r = sb.run(cmd)
    if r.returncode not in (0, 1) or not r.stdout.strip():
        return f"(no definition found for {name!r})"

    seen_paths: set[str] = set()
    hits: list[tuple[str, int]] = []
    for line in r.stdout.strip().splitlines():
        m = re.match(r"([^:]+):(\d+):", line)
        if not m:
            continue
        path, ln = m.group(1), int(m.group(2))
        # Only take one hit per file, first definition-shaped one
        if path in seen_paths:
            continue
        seen_paths.add(path)
        hits.append((path, ln))
        if len(hits) >= 3:
            break

    if not hits:
        return f"(no definition found for {name!r})"

    out: list[str] = []
    for path, ln in hits:
        try:
            body = sb.read(path)
        except SandboxError:
            continue
        lines = body.splitlines()
        start_idx = ln - 1
        depth = 0
        started = False
        end_idx = start_idx
        for i in range(start_idx, min(start_idx + 800, len(lines))):
            for ch in lines[i]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth == 0:
                end_idx = i
                break
        if not started:
            out.append(f"--- {path}:{ln} (prototype only, no body found) ---\n"
                       f"{lines[start_idx]}")
            continue
        snippet_lines = [f"{start_idx + j + 1:5d}  {lines[start_idx + j]}"
                         for j in range(end_idx - start_idx + 1)]
        snippet = "\n".join(snippet_lines)
        out.append(f"--- {path}:{ln} ---\n{snippet}")

    combined = "\n\n".join(out)
    return _clip(combined, 40000, "function view")


TOOLS = {
    "read_file": read_file,
    "list_dir": list_dir,
    "grep": grep,
    "show_function": show_function,
}


TOOL_SPEC = """You can call any of these tools. Return them as `tool_calls` in your JSON reply.

- read_file(path): return the full contents of a file from the source tree.
    args: {"path": "SAX2.c"}   or absolute: {"path": "/src/libxml2/parser.c"}
- list_dir(path): list entries in a directory.
    args: {"path": "/src/libxml2"}
- grep(pattern, path_glob): grep for a pattern across files matching a glob.
    args: {"pattern": "xmlAddChild", "path_glob": "*.c"}
    optional args: {"root": "/src/libxml2"} (defaults to current dir)
- show_function(name): locate a function's definition by name and return its
    body with line numbers.
    args: {"name": "xmlSAX2CDataBlock"}

You may call up to 5 tools per turn. Paths may be relative to the source root
or absolute (starting with /). Errors from a tool come back as an "error"
field in that call's result — use them to adjust your next call.
"""
