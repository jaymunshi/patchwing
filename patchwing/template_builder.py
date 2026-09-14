"""Machine-derived pod template builder.

The one non-negotiable: every template's recipe is captured by RUNNING
the recipe against a fresh pod using the actual provision tools
(exec_in_pod, write_file_to_pod, install_package, http_probe). No
Dockerfile shortcuts, no direct subprocess calls that bypass the tool
layer. The point of the recipe artifact is provenance: a reader who
knows only the provision tools can replay a template's build exactly.

Recipe-fn shape:
    def build_tomcat(rec):
        rec.install_package("openjdk-8-jdk")
        rec.install_package("maven")
        rec.exec_in_pod("cd /opt && wget https://... && tar -xzf ...")
        rec.write_file_to_pod("/opt/tomcat9/bin/setenv.sh", "...")
        return {
            "verification_cmd":
                "/opt/tomcat9/bin/startup.sh && sleep 10 "
                "&& curl -sSi http://127.0.0.1:8080/",
            "verification_expect": r"HTTP/1\\.1 200.*Apache Tomcat",
        }

build_template runs the recipe against a fresh pod, commits the pod,
brings up a SEPARATE verification pod from the committed image, runs
verification_cmd, matches stdout against verification_expect regex,
persists on success — or removes the image and raises on failure so a
DB row is never created for an unverified template.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from . import provision as provision_mod
from . import sandbox as sandbox_mod
from . import templates as tpl_mod


# --- exceptions -----------------------------------------------------------

class BuildFailed(Exception):
    """Any stage of template build failed. `stage` names WHICH stage
    (precheck, pod_create, recipe, commit, inspect, verify_pod_create,
    verify_exec, verify_expect_mismatch, persist). `stdout_tail` carries
    the last 4KB of the failing command's output on stages that produce
    it — the reader shouldn't have to grep server logs to see what broke."""

    def __init__(self, stage: str, message: str,
                 stdout_tail: str = ""):
        self.stage = stage
        self.message = message
        self.stdout_tail = stdout_tail or ""
        super().__init__(f"{stage}: {message}")


class VerificationFailed(BuildFailed):
    """The template built + committed, but the verification pod's output
    did not match the expected regex. The committed image is REMOVED
    before this raises, so we never leave an orphaned tag without a DB
    row. Subclasses BuildFailed so callers can pattern-match on shape
    while still special-casing verification failures for reporting."""


# --- recorder -------------------------------------------------------------

class TemplateRecorder:
    """Wraps a Sandbox. Exposes the four provision-tool methods; every
    call is recorded to `self.recipe` (in order) and then delegated to
    the actual tool in `patchwing.provision`. That way the recipe_fn
    reads as idiomatic Python (rec.install_package("openjdk-8-jdk"))
    while the recipe artifact captures exactly which provision tool
    was invoked and with what arguments.

    Bypass paths are impossible by construction: the recorder does not
    expose a passthrough to the raw sandbox, so a recipe_fn that wants
    to run a command has to go through exec_in_pod, which records. A
    recipe_fn that reaches for provision_mod directly would be
    obviously wrong on inspection."""

    def __init__(self, sb):
        self._sb = sb
        self.recipe: list[dict] = []

    def exec_in_pod(self, cmd: str, timeout_s: int = 60) -> str:
        self.recipe.append({"tool": "exec_in_pod",
                            "args": {"cmd": cmd,
                                     "timeout_s": int(timeout_s)}})
        return provision_mod.exec_in_pod(self._sb, cmd, timeout_s)

    def write_file_to_pod(self, path: str, content: str) -> str:
        self.recipe.append({"tool": "write_file_to_pod",
                            "args": {"path": path, "content": content}})
        return provision_mod.write_file_to_pod(self._sb, path, content)

    def install_package(self, name: str, timeout_s: int = 600) -> str:
        self.recipe.append({"tool": "install_package",
                            "args": {"name": name,
                                     "timeout_s": int(timeout_s)}})
        return provision_mod.install_package(self._sb, name, timeout_s)

    def http_probe(self, url: str, method: str = "GET",
                   headers: Optional[dict] = None,
                   body: str = "") -> str:
        self.recipe.append({"tool": "http_probe",
                            "args": {"url": url, "method": method,
                                     "headers": dict(headers or {}),
                                     "body": body}})
        return provision_mod.http_probe(
            self._sb, url, method, headers, body)

    # --- raise-on-nonzero variants for deterministic machine recipes ----
    # exec_in_pod and install_package return non-zero as DATA (the LLM
    # provision loop needs to read exit codes to adapt). Template recipes
    # are deterministic Python code where a non-zero apt-get or shell
    # chain is a real failure the build should halt on. These variants
    # do that halt — they still record through the same provision tool
    # (provenance stays intact), just escalate a non-zero exit into a
    # ToolError so the outer build_template sees it as a `recipe` stage
    # failure with useful context.

    def exec_or_raise(self, cmd: str, timeout_s: int = 60) -> str:
        """exec_in_pod that RAISES ToolError on non-zero exit. Use for
        every step in a deterministic recipe where a failure means the
        template is broken (not context to iterate on)."""
        out = self.exec_in_pod(cmd, timeout_s=timeout_s)
        if not out.startswith("exit 0 "):
            from .tools import ToolError
            raise ToolError(
                f"exec_in_pod exit non-zero on {cmd[:80]!r}: {out[:600]}")
        return out

    def install_or_raise(self, name: str, timeout_s: int = 600) -> str:
        """install_package that RAISES ToolError on non-zero apt-get exit."""
        out = self.install_package(name, timeout_s=timeout_s)
        if not out.startswith("exit 0 "):
            from .tools import ToolError
            raise ToolError(
                f"install_package exit non-zero on {name!r}: {out[:600]}")
        return out


# --- build result --------------------------------------------------------

@dataclass
class BuildResult:
    template: Any                      # PodTemplate — the persisted row
    turns: int
    build_seconds: int
    image_size_bytes: Optional[int]
    image_digest: str
    verification_stdout: str


# --- subprocess helpers (podman/docker inspect + rmi) --------------------
# Module-level so tests can monkey-patch. All timeouts explicit; all
# errors caught + re-raised as BuildFailed so a reader who only sees the
# error can act on the stage name.

def _image_digest(backend: str, tag: str) -> str:
    try:
        r = subprocess.run(
            [backend, "inspect", "--format", "{{.Id}}", tag],
            capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as e:
        raise BuildFailed("inspect", f"digest fetch timeout on {tag}: {e}")
    except FileNotFoundError as e:
        raise BuildFailed("inspect", f"{backend} not found: {e}")
    if r.returncode != 0:
        raise BuildFailed(
            "inspect",
            f"digest fetch failed on {tag}: exit {r.returncode}",
            stdout_tail=((r.stdout or "") + (r.stderr or ""))[-2000:])
    d = (r.stdout or "").strip()
    if not d:
        raise BuildFailed("inspect", f"digest fetch returned empty for {tag}")
    return d


def _image_size_bytes(backend: str, tag: str) -> Optional[int]:
    try:
        r = subprocess.run(
            [backend, "inspect", "--format", "{{.Size}}", tag],
            capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None       # size is a nice-to-have; never a build blocker
    if r.returncode != 0:
        return None
    try:
        return int((r.stdout or "").strip())
    except (ValueError, TypeError):
        return None


def _remove_image(backend: str, tag: str) -> None:
    """Best-effort. If the tag is already gone (or never existed),
    silently succeed — this only runs on failure paths where we're
    trying to clean up."""
    try:
        subprocess.run([backend, "rmi", "-f", tag],
                       capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


# --- build_template ------------------------------------------------------

def verify_template(*, store, sandbox_config, template) -> dict:
    """Re-run the verification for an already-persisted template.

    Spawns a fresh pod from `template.image_tag`, runs
    `template.verification_cmd`, matches stdout against
    `template.verification_expect`. Updates the row's
    `last_verified_at / last_verified_ok / last_verified_note`
    atomically via the store. Returns a dict with the result so the
    verify-now UI button can render feedback without a second DB read.

    Does NOT touch the image itself — no commit, no digest check, no
    delete on failure. Verification failure here just means "the stack
    is broken RIGHT NOW", not "the image is corrupt." A future digest-
    drift check would be a separate helper.
    """
    verify_pod = sandbox_mod.make(
        sandbox_config,
        workdir=".patchwing-tpl-reverify",
        spec={"target": {"image": template.image_tag,
                         "mode": "in-image",
                         "root": "/"}},
        persist=False)
    stdout_tail = ""
    ok = False
    error = ""
    try:
        try:
            verify_pod.prepare()
        except sandbox_mod.SandboxError as e:
            error = f"pod prep failed: {e}"
        else:
            try:
                r = verify_pod.run(template.verification_cmd, timeout_s=300)
                stdout = ((r.stdout or "")
                          + (("\n[stderr]\n" + r.stderr) if r.stderr else ""))
                stdout_tail = stdout[-4000:]
                try:
                    expect_re = re.compile(template.verification_expect,
                                           re.S)
                except re.error as e:
                    error = f"verification_expect regex invalid: {e}"
                else:
                    ok = bool(expect_re.search(stdout))
                    if not ok:
                        error = (f"verification stdout did not match "
                                 f"/{template.verification_expect}/")
            except sandbox_mod.SandboxError as e:
                error = f"verification command failed to execute: {e}"
    finally:
        try:
            verify_pod.cleanup()
        except Exception:
            pass

    # Persist the outcome — success carries the stdout tail as note,
    # failure carries the error + tail so the UI can show what broke.
    note = stdout_tail[-800:] if ok else (
        f"{error}\n---stdout---\n{stdout_tail}"[-1800:])
    store.update_template_verification(template.id, ok=ok, note=note)

    return {"ok": ok, "error": error, "stdout_tail": stdout_tail}


def build_template(*,
                   store,
                   sandbox_config,
                   name: str,
                   description: str,
                   base_image: str,
                   cve_class_hint: Optional[str],
                   recipe_fn: Callable[[TemplateRecorder], dict],
                   ) -> BuildResult:
    """Build a template from a machine-callable recipe function.

    On success: persists a pod_templates row, records verification=ok,
    returns BuildResult.

    On failure: raises BuildFailed (or VerificationFailed). The DB is
    NOT written. The committed image, if it was created, is removed so
    we never leave an orphaned tag without a row.

    Args:
      store: patchwing.Store — where the template row lands.
      sandbox_config: patchwing.config.SandboxConfig — backend selection.
      name: template name; goes into `patchwing-template:<name>` tag.
      description: human-readable.
      base_image: e.g. 'ubuntu:22.04'.
      cve_class_hint: e.g. 'java-servlet-web-rce'. May be None.
      recipe_fn: callable(recorder) -> dict. Must return a dict with
                 non-empty `verification_cmd` and `verification_expect`.
    """
    started = time.time()

    # Precheck — refuse a duplicate name so we don't waste minutes of
    # build only to hit IntegrityError at persist.
    if store.get_template(name) is not None:
        raise BuildFailed(
            "precheck",
            f"template name {name!r} already exists; delete it first "
            f"before rebuilding")

    try:
        image_tag = tpl_mod.image_tag_for(name)
    except ValueError as e:
        raise BuildFailed("precheck", str(e))

    # 1. Build pod from base_image
    build_pod = sandbox_mod.make(
        sandbox_config,
        workdir=".patchwing-tpl-build",
        spec={"target": {"image": base_image,
                         "mode": "in-image",
                         "root": "/"}},
        persist=False)
    committed = False
    try:
        try:
            build_pod.prepare()
        except sandbox_mod.SandboxError as e:
            raise BuildFailed(
                "pod_create",
                f"failed to bring up build pod on {base_image}: {e}")

        # 2. Run the recipe against the recorder — every tool call
        # captured in order, every one delegated to the real provision
        # tool. No shortcuts possible.
        recorder = TemplateRecorder(build_pod)
        try:
            verification_meta = recipe_fn(recorder)
        except BuildFailed:
            raise
        except Exception as e:
            raise BuildFailed(
                "recipe",
                f"recipe_fn raised: {type(e).__name__}: {e}")

        if not isinstance(verification_meta, dict):
            raise BuildFailed(
                "recipe",
                f"recipe_fn must return a dict, got "
                f"{type(verification_meta).__name__}")
        verification_cmd = (verification_meta.get("verification_cmd")
                            or "").strip()
        verification_expect = (verification_meta.get("verification_expect")
                               or "").strip()
        if not verification_cmd or not verification_expect:
            raise BuildFailed(
                "recipe",
                "recipe_fn's returned dict must set BOTH "
                "verification_cmd and verification_expect (non-empty). "
                "Split so the runner can present them separately in the UI "
                "and a template cannot smuggle its own verification bar "
                "into the command.")

        # Compile the regex once so a bad regex fails at build, not at
        # every verify-now click later.
        try:
            expect_re = re.compile(verification_expect, re.S)
        except re.error as e:
            raise BuildFailed(
                "recipe",
                f"verification_expect is not a valid regex: {e}")

        # 3. Commit — captures the FS state as a new image tag
        try:
            provision_mod.commit_pod(build_pod, image_tag)
            committed = True
        except sandbox_mod.SandboxError as e:
            raise BuildFailed("commit", f"pod commit failed: {e}")

        # 4. Inspect — digest is load-bearing (tags drift, digests don't)
        backend = getattr(build_pod, "backend", "podman")
        try:
            digest = _image_digest(backend, image_tag)
        except BuildFailed:
            _remove_image(backend, image_tag)
            raise
        size_bytes = _image_size_bytes(backend, image_tag)
    finally:
        # Build pod is done — its state is either in the committed image
        # (success) or we failed and don't need it either way.
        try:
            build_pod.cleanup()
        except Exception:
            pass

    # 5. Verification — FRESH pod from the committed image (not the
    # already-running build pod, which has state that could mask a bad
    # commit). Run verification_cmd, match stdout against expect regex.
    verify_pod = sandbox_mod.make(
        sandbox_config,
        workdir=".patchwing-tpl-verify",
        spec={"target": {"image": image_tag,
                         "mode": "in-image",
                         "root": "/"}},
        persist=False)
    stdout_tail = ""
    try:
        try:
            verify_pod.prepare()
        except sandbox_mod.SandboxError as e:
            _remove_image(backend, image_tag)
            raise BuildFailed(
                "verify_pod_create",
                f"failed to bring up verification pod from {image_tag}: {e}")
        try:
            r = verify_pod.run(verification_cmd, timeout_s=300)
        except sandbox_mod.SandboxError as e:
            _remove_image(backend, image_tag)
            raise BuildFailed(
                "verify_exec",
                f"verification command failed to execute: {e}")
        stdout = ((r.stdout or "")
                  + (("\n[stderr]\n" + r.stderr) if r.stderr else ""))
        stdout_tail = stdout[-4000:]
        if not expect_re.search(stdout):
            _remove_image(backend, image_tag)
            raise VerificationFailed(
                "verify_expect_mismatch",
                f"verification stdout did not match "
                f"/{verification_expect}/ — see stdout_tail for what "
                f"actually came back",
                stdout_tail=stdout_tail)
    finally:
        try:
            verify_pod.cleanup()
        except Exception:
            pass

    # 6. Persist — everything checks out; write the row + record the
    # verification success in the same transaction from the caller's
    # point of view (two calls, but store.add_template commits so a
    # crash between them just means the template exists as unverified —
    # verify-now clears that on next click).
    recipe_json = json.dumps(recorder.recipe, indent=2, sort_keys=True)
    persisted = store.add_template(
        name=name,
        description=description,
        base_image=base_image,
        image_tag=image_tag,
        image_size_bytes=size_bytes,
        image_digest=digest,
        recipe_json=recipe_json,
        recipe_turn_count=len(recorder.recipe),
        verification_cmd=verification_cmd,
        verification_expect=verification_expect,
        cve_class_hint=cve_class_hint,
        builder_version=tpl_mod.BUILDER_VERSION_CURRENT)
    store.update_template_verification(
        persisted.id, ok=True, note=stdout_tail[-800:])

    return BuildResult(
        template=store.get_template(persisted.id),
        turns=len(recorder.recipe),
        build_seconds=int(time.time() - started),
        image_size_bytes=size_bytes,
        image_digest=digest,
        verification_stdout=stdout_tail)
