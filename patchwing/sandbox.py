"""
Where target code actually runs.

Two backends today: `local` (subprocess against a throwaway copy of the tree)
and `podman`/`docker` (not yet implemented). Everything sits behind one
interface so the execution boundary can be tightened without touching stages —
and so a host-level Firecracker backend stays possible on hardware that supports
it.

`local` provides *no* isolation beyond working on a copy. It is only safe inside
a disposable VM, which is why config warns when you select it.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass


@dataclass
class RunResult:
    cmd: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def tail(self, n: int = 2000) -> str:
        out = (self.stdout or "") + (("\n[stderr]\n" + self.stderr) if self.stderr else "")
        return out[-n:] if len(out) > n else out


class SandboxError(Exception):
    pass


class LocalSandbox:
    """Runs commands against a private copy of the target tree."""

    backend = "local"

    def __init__(self, workdir: str = ".patchwing", timeout_s: int = 1800,
                 env: dict | None = None):
        self.root = os.path.abspath(workdir)
        self.timeout_s = timeout_s
        self.dir: str | None = None
        self.env = env or {}

    def prepare(self, src_dir: str) -> str:
        src = os.path.abspath(src_dir)
        if not os.path.isdir(src):
            raise SandboxError(f"target path is not a directory: {src}")
        os.makedirs(self.root, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="run-", dir=self.root)
        # copy2 preserves mtimes so build systems behave
        shutil.copytree(src, self.dir, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(
                            "__pycache__", "*.pyc", ".git", ".patchwing"))
        return self.dir

    def run(self, cmd: str, cwd: str | None = None,
            timeout_s: int | None = None, timeout: int | None = None) -> RunResult:
        # `timeout_s` is the canonical keyword across all three sandbox classes
        # (InImageSandbox — the live in-image path — has always used it, and all
        # 12 call sites pass `timeout_s=`). `timeout` is kept as a backward-compat
        # alias so a legacy caller cannot break. Before this unification, passing
        # `timeout_s=` to a Local/ContainerSandbox raised TypeError, which the
        # runner swallowed as INFRASTRUCTURE_FAILURE — a harness fault mislabelled.
        _to = timeout_s if timeout_s is not None else timeout
        if not cmd.strip():
            return RunResult(cmd, 0, "", "", 0.0)
        if self.dir is None:
            raise SandboxError("prepare() must be called before run()")

        env = dict(os.environ)
        # Keep output deterministic and stop Python writing caches into the copy
        env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8",
                    "PYTHONUNBUFFERED": "1", "NO_COLOR": "1"})
        env.update(self.env)

        started = time.time()
        try:
            p = subprocess.run(
                cmd, shell=True, cwd=cwd or self.dir, env=env,
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=_to or self.timeout_s,
            )
            return RunResult(cmd, p.returncode, p.stdout or "", p.stderr or "",
                             time.time() - started)
        except subprocess.TimeoutExpired as e:
            return RunResult(cmd, -1,
                             (e.stdout or b"").decode("utf-8", "replace")
                             if isinstance(e.stdout, bytes) else (e.stdout or ""),
                             "timed out", time.time() - started, timed_out=True)

    # -- file access inside the sandbox ----------------------------------



    def run_ephemeral(self, cmd: str, *, network: str,
                       timeout_s: int | None = None,
                       cwd: str | None = None) -> RunResult:
        """First-class hermeticity primitive. Not applicable to LocalSandbox
        (no container isolation available). Callers requesting hermeticity
        against a LocalSandbox get an honest error, not silent success."""
        raise NotImplementedError(
            "run_ephemeral requires a container backend; LocalSandbox has no "
            "network namespace to isolate. Use ContainerSandbox or "
            "InImageSandbox for hermetic runs.")

    def path(self, rel: str) -> str:
        if self.dir is None:
            raise SandboxError("prepare() must be called first")
        full = os.path.abspath(os.path.join(self.dir, rel))
        # Containment check — the same class of bug PatchWing exists to fix.
        if not full.startswith(os.path.abspath(self.dir) + os.sep) and full != os.path.abspath(self.dir):
            raise SandboxError(f"path escapes the sandbox: {rel}")
        return full

    def read(self, rel: str) -> str:
        with open(self.path(rel), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def write(self, rel: str, content: str) -> None:
        full = self.path(rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)

    def exists(self, rel: str) -> bool:
        try:
            return os.path.exists(self.path(rel))
        except SandboxError:
            return False

    def cleanup(self) -> None:
        if self.dir and os.path.isdir(self.dir):
            shutil.rmtree(self.dir, ignore_errors=True)
        self.dir = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
        return False


class ContainerSandbox(LocalSandbox):
    """
    Run each command inside a fresh, network-isolated podman/docker container —
    the disposable "staging cell". The target tree is prepared on disk exactly
    as for LocalSandbox, then bind-mounted into the container at /work.

    The container's image carries the toolchain (python:3.12-slim, node:20-slim,
    a JDK+Maven image, …), so the VM host stays clean and each target gets a
    matching build environment. Nothing here needs a nested hypervisor.
    """

    DEFAULT_IMAGE = "docker.io/library/python:3.12-slim"

    def __init__(self, backend: str, image: str = "", network: str = "none",
                 cpus: float = 2.0, memory: str = "4g", *a, **kw):
        super().__init__(*a, **kw)
        self.backend = backend
        self.image = image or self.DEFAULT_IMAGE
        self.network = network
        self.cpus = cpus
        self.memory = memory

    def run(self, cmd: str, cwd: str | None = None,
            timeout_s: int | None = None, image: str | None = None,
            timeout: int | None = None) -> RunResult:
        # `timeout_s` canonical, `timeout` back-compat alias — see LocalSandbox.run.
        _to = timeout_s if timeout_s is not None else timeout
        if not cmd.strip():
            return RunResult(cmd, 0, "", "", 0.0)
        if self.dir is None:
            raise SandboxError("prepare() must be called before run()")

        img = image or self.image
        wd = "/work"
        if cwd and cwd != self.dir:
            rel = os.path.relpath(cwd, self.dir).replace(os.sep, "/")
            wd = f"/work/{rel}" if rel != "." else "/work"

        argv = [
            self.backend, "run", "--rm",
            "--network", self.network,
            "--memory", self.memory, "--cpus", str(self.cpus),
            "--pids-limit", "512",
            "--userns=keep-id",                 # files owned by the run user
            "-v", f"{self.dir}:/work:Z",
            "-w", wd,
            "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONUNBUFFERED=1",
            "--env", "NO_COLOR=1",
            img, "bash", "-lc", cmd,  # bash for pipefail (dash chokes)
        ]

        started = time.time()
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=_to or self.timeout_s,
            )
            return RunResult(cmd, p.returncode, p.stdout or "", p.stderr or "",
                             time.time() - started)
        except subprocess.TimeoutExpired as e:
            out = e.stdout or ""
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            return RunResult(cmd, -1, out, "container timed out",
                             time.time() - started, timed_out=True)
        except FileNotFoundError:
            raise SandboxError(
                f"'{self.backend}' not found — is it installed on this host? "
                f"The sandbox is meant to run on the provisioned VM.")


def make(cfg, workdir: str = ".patchwing", spec: dict | None = None,
         existing_cid: str = "", persist: bool = False,
         network: str | None = None) -> LocalSandbox:
    """Build a sandbox from a SandboxConfig, and optionally a target spec.

    A spec declaring `mode = "in-image"` selects the containerised-target adapter:
    the source lives inside the image and is patched in place. Everything else gets
    the historical host-copytree path.

    `existing_cid` / `persist` implement pod-per-finding (change 2). When a
    finding already has a container_id from an earlier stage, the caller passes
    it here to attach instead of creating a fresh pod. `persist=True` keeps the
    pod alive across cleanup so the next stage can attach the same way.
    """
    tgt = ((spec or {}).get("target") or {}) if spec else {}
    # `network` kwarg overrides cfg.network — provision passes it
    # explicitly so its pods can talk to github/maven/apt while every
    # other stage falls through to cfg.network (default "none").
    _network = network if network is not None else cfg.network
    if str(tgt.get("mode", "")).replace("_", "-") == "in-image":
        return InImageSandbox(
            cfg.backend if cfg.backend in ("podman", "docker") else "podman",
            image=tgt.get("image") or cfg.image,
            root=tgt.get("root", "/src"),
            network=_network, cpus=cfg.cpus, memory=cfg.memory,
            workdir=workdir, timeout_s=cfg.timeout_s,
            existing_cid=existing_cid, persist=persist)
    if cfg.backend in ("podman", "docker"):
        return ContainerSandbox(cfg.backend, image=cfg.image,
                                network=_network, cpus=cfg.cpus,
                                memory=cfg.memory, workdir=workdir,
                                timeout_s=cfg.timeout_s)
    return LocalSandbox(workdir=workdir, timeout_s=cfg.timeout_s)


class InImageSandbox(LocalSandbox):
    """A target that lives INSIDE a container image, patched in place.

    LocalSandbox and ContainerSandbox both assume the source is a host directory:
    prepare() copytrees it, and ContainerSandbox bind-mounts that copy at /work.
    That model does not fit OSS-Fuzz-derived corpora, and the mismatch is not
    cosmetic:

      * There is no host-side source at all. ARVO bakes the tree into the image at
        /src, with the build environment around it.
      * /work is already used by the image's own build (`mkdir /work/libfuzzer`),
        so bind-mounting over it breaks compilation.

    Relocating the mount would only dodge the collision. We would still be copying
    the tree out, patching it, copying it back, and then arguing that our
    reconstruction of ARVO's build environment is faithful. In-image needs no such
    argument.

    The decisive reason is the evidence package. Patching in place makes the
    reproduction instruction: *pull this image digest, apply this diff, run these
    two commands*. A third party re-runs it against the corpus's own published
    image and trusts nothing of ours — not our copy of the tree, not our toolchain.
    That is the portable red-to-green proof in its strongest available form.

    This is deliberately a GENERAL containerised-target adapter, not an ARVO special
    case: every OSS-Fuzz-derived corpus bakes source into the image, so
    AutoPatchBench and anything downstream hits the same wall. The host-copytree
    path is now the special case, for checked-out trees.

    **One container per `with` block = one attempt.** Commands within an attempt see
    each other (a patch must be visible to the build that follows it), but no
    attempt inherits state from the previous one. A persistent container across
    attempts would give incremental builds — turning ~23 minutes into a few — at the
    cost of letting attempt N+1 observe attempt N's artifacts. That is a
    contamination path, so it is offered as an optimization elsewhere and never
    taken while proving a result.
    """

    # Mount point for diff-in / evidence-out. Verified absent in the ARVO image;
    # /src, /out and /work are taken, and /workspace is referenced by the
    # sanitizers' strip_path_prefix even though it does not exist.
    MOUNT = "/patchwing"

    def __init__(self, backend: str, image: str, root: str = "/src",
                 network: str = "none", cpus: float = 2.0, memory: str = "4g",
                 workdir: str = ".patchwing", timeout_s: int = 1800,
                 existing_cid: str = "", persist: bool = False):
        super().__init__(workdir=workdir, timeout_s=timeout_s)
        if not image:
            raise SandboxError("in-image mode requires an image")
        self.backend = backend or "podman"
        self.image = image
        # Normalize root:
        #   ""   → historical default "/src" (ARVO/OSS-Fuzz corpora that bake
        #          source at /src)
        #   "/"  → the image's actual root (templates + generic containers
        #          where the target has no dedicated source root)
        #   "/x" → x with any trailing slashes stripped
        # The old rule was `root.rstrip("/") or "/src"`, which collapsed "/"
        # to "" and then fell through to "/src" — a subtle bug because
        # provision/templates set root="/" for bare ubuntu, then every
        # `podman exec -w /src` chdir'd to a nonexistent directory (silently
        # non-zero'd for install_package, escalated for write_file_to_pod).
        if root == "/":
            self.src_root = "/"
        else:
            self.src_root = root.rstrip("/") or "/src"
        self.network = network
        self.cpus = cpus
        self.memory = memory
        # Pod-per-finding: if existing_cid is set, we attach to that container
        # instead of creating a fresh one. `persist=True` means cleanup() does
        # NOT tear the pod down — it stays alive for the next stage.
        self.existing_cid = (existing_cid or "").strip()
        self.persist = persist
        self.cid = ""

    class PodLost(SandboxError):
        """Raised when an existing_cid was supplied but the container no longer
        exists. Distinct type so callers can map to POD_LOST_FINDING_TERMINATED
        instead of a generic SandboxError."""

    # -- lifecycle --------------------------------------------------------

    def prepare(self, src_dir: str = "") -> str:
        """Start the attempt container, OR attach to an existing one.

        If `existing_cid` was supplied, verify it is still alive via
        `podman inspect` and reuse it. Podman reporting "no such container"
        raises PodLost — the caller should treat this as a terminal signal
        for the finding, NOT retry (the reproducer is non-deterministic and
        a new pristine could match a different DEDUP_TOKEN).
        """
        os.makedirs(self.root, exist_ok=True)
        if self.existing_cid:
            p = subprocess.run(
                [self.backend, "inspect", "-f", "{{.State.Running}}",
                 self.existing_cid],
                capture_output=True, text=True, timeout=30)
            if p.returncode != 0 or "true" not in (p.stdout or "").lower():
                raise self.PodLost(
                    f"container {self.existing_cid[:12]} no longer exists "
                    f"(or is not running). The finding's chain of custody is "
                    f"broken; do NOT create a fresh pod under the same "
                    f"pristine. Start a new finding from the spec.")
            self.cid = self.existing_cid
            self.dir = tempfile.mkdtemp(prefix="inimg-", dir=self.root)
            return self.src_root

        self.dir = tempfile.mkdtemp(prefix="inimg-", dir=self.root)
        cmd = [
            self.backend, "run", "-d", "--rm",
            f"--network={self.network}",
            f"--cpus={self.cpus}", f"--memory={self.memory}",
            "-v", f"{self.dir}:{self.MOUNT}:Z",
            self.image, "sleep", "infinity",
        ]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if p.returncode != 0:
            raise SandboxError(f"cannot start container from {self.image}: "
                               f"{(p.stderr or p.stdout)[:400]}")
        self.cid = (p.stdout or "").strip()
        if not self.cid:
            raise SandboxError("container started but returned no id")
        return self.src_root

    def cleanup(self) -> None:
        # Persistent pods survive cleanup — the finding's next stage will
        # attach via existing_cid. The container is only torn down when the
        # finding transitions to a terminal state (runner._advance for
        # DONE/REJECTED/FAILED with pod present) OR when the caller
        # explicitly stops it.
        if self.persist:
            self.cid = ""
            super().cleanup()
            return
        if self.cid:
            subprocess.run([self.backend, "rm", "-f", self.cid],
                           capture_output=True, text=True)
            self.cid = ""
        super().cleanup()

    # -- execution --------------------------------------------------------

    def run(self, cmd: str, cwd: str | None = None,
            timeout_s: int | None = None, timeout: int | None = None) -> RunResult:
        # `timeout_s` canonical; `timeout` back-compat alias for signature parity
        # with the other two sandbox classes (see LocalSandbox.run).
        timeout_s = timeout_s if timeout_s is not None else timeout
        if not cmd.strip():
            return RunResult(cmd, 0, "", "", 0.0)
        if not self.cid:
            raise SandboxError("prepare() must be called before run()")
        workdir = cwd or self.src_root
        full = [self.backend, "exec", "-w", workdir, self.cid, "bash", "-lc", cmd]  # bash for pipefail (dash chokes)
        t0 = time.time()
        try:
            # Capture bytes and decode with errors='replace' so a file with
            # non-UTF-8 content (libxml2's docs carry Latin-1 fragments) does
            # not raise UnicodeDecodeError out of the tool dispatch and take
            # down the whole investigation loop. Turning the decode into
            # replacement chars keeps the byte offsets stable enough for line
            # counters and grep matching that surface in the tool output.
            p = subprocess.run(full, capture_output=True, text=False,
                               timeout=timeout_s or self.timeout_s)
            stdout = (p.stdout or b"").decode("utf-8", errors="replace")
            stderr = (p.stderr or b"").decode("utf-8", errors="replace")
            return RunResult(cmd, p.returncode, stdout, stderr,
                             time.time() - t0)
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or b"").decode("utf-8", "replace") if e.stdout else ""
            return RunResult(cmd, -1, out, "container timed out",
                             time.time() - t0, timed_out=True)

    # -- file access, all relative to `root` INSIDE the image --------------

    def path(self, rel: str) -> str:
        # Strip trailing slash off src_root so root='/' + rel does not produce //rel.
        if rel.startswith("/"):
            return rel
        base = (self.src_root or "/").rstrip("/")
        return f"{base}/{rel}"



    def run_ephemeral(self, cmd: str, *, network: str,
                       timeout_s: int | None = None,
                       cwd: str | None = None) -> RunResult:
        """Spin a fresh short-lived --rm container from this sandbox's
        image with an EXPLICIT network posture. Does NOT touch the
        persistent pod. Used for hermeticity smoke builds (network=none)
        and any other one-shot isolated execution against the same image.

        `network` is REQUIRED (no default) — callers must name the
        security posture per-call. That is the whole point of this method:
        `run()` uses the persistent pod's network baked in at prepare();
        this method lets a caller override for a single command without
        affecting the pod.

        Same resource limits (memory, cpus, backend) as the persistent
        pod. Same working directory default (self.src_root)."""
        if not cmd.strip():
            return RunResult(cmd, 0, "", "", 0.0)
        if not self.image:
            raise SandboxError(
                "run_ephemeral requires self.image to be set — it spawns "
                "a fresh container from that image")
        workdir = cwd or self.src_root or "/"
        argv = [
            self.backend, "run", "--rm",
            f"--network={network}",
            "--memory", self.memory, "--cpus", str(self.cpus),
            "--pids-limit", "512",
            "-w", workdir,
            self.image, "bash", "-lc", cmd,  # bash for pipefail (dash chokes)
        ]
        t0 = time.time()
        try:
            p = subprocess.run(argv, capture_output=True, text=False,
                               timeout=timeout_s or self.timeout_s)
            stdout = (p.stdout or b"").decode("utf-8", errors="replace")
            stderr = (p.stderr or b"").decode("utf-8", errors="replace")
            return RunResult(cmd, p.returncode, stdout, stderr,
                             time.time() - t0)
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or b"").decode("utf-8", "replace") if e.stdout else ""
            return RunResult(cmd, -1, out, "ephemeral container timed out",
                             time.time() - t0, timed_out=True)

    def read(self, rel: str) -> str:
        r = self.run(f"cat {shlex.quote(self.path(rel))}")
        if r.returncode != 0:
            raise SandboxError(f"cannot read {rel} in image: {r.stderr[:200]}")
        return r.stdout

    def write(self, rel: str, content: str) -> None:
        """Write a file inside the image via `podman cp`, not the bind mount.

        Prior implementation staged through the mount at self.MOUNT and shelled
        `cp` inside the container. That breaks under pod-per-finding (change 2)
        because when we ATTACH to an existing pod, the container's original
        bind mount was set up in `podman run` and points at a host tempdir
        that the previous stage's cleanup deleted. A new tempdir on the host
        is not the same mount inside the container.

        `podman cp host_path CID:container_path` copies through podman's own
        machinery without needing any bind mount to be current. Same anti-
        corruption property as the old code (no shell quoting of file
        contents) — the bytes go via podman's tar-based transfer.
        """
        if not self.cid:
            raise SandboxError("prepare() must be called before write()")
        # Ensure parent dir exists inside the container. Cheap.
        dest = self.path(rel)
        mk = self.run(f"mkdir -p {shlex.quote(os.path.dirname(dest))}")
        if mk.returncode != 0:
            raise SandboxError(f"cannot create parent dir for {rel} in "
                               f"image: {mk.stderr[:200]}")
        # Stage bytes on the host and copy them in.
        stage = os.path.join(self.dir or tempfile.gettempdir(), "stage.blob")
        os.makedirs(os.path.dirname(stage) or ".", exist_ok=True)
        with open(stage, "w", encoding="utf-8") as fh:
            fh.write(content)
        p = subprocess.run(
            [self.backend, "cp", stage, f"{self.cid}:{dest}"],
            capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            raise SandboxError(f"cannot write {rel} in image: "
                               f"{(p.stderr or p.stdout)[:200]}")

    def exists(self, rel: str) -> bool:
        return self.run(f"test -e {shlex.quote(self.path(rel))}").returncode == 0

    def md5(self, abs_path: str) -> str:
        """Hash a file inside the image. Used to assert the build actually
        produced a new binary after a patch."""
        r = self.run(f"md5sum {shlex.quote(abs_path)} 2>/dev/null | cut -d' ' -f1")
        return (r.stdout or "").strip()
