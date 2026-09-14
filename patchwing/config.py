"""
Configuration: per-role model endpoints, sandbox, and pipeline limits.

Two rules shape this file.

**Per-role, never global.** `detect`, `patch` and `verify` each get their own
endpoint, model and key. A single global model would silently destroy the
different-family verifier property the moment someone swapped providers, so the
loader warns when the verifier and the fixer look like the same lineage.

**Keys come from the environment, not from this file.** A security tool must not
teach people to commit credentials. `api_key_env` names a variable; `api_key`
inline is allowed only for local endpoints that ignore auth anyway.

There is deliberately **no default provider**. Whatever a security tool names in
its config ships as an endorsement, and some buyers will not send code and
exploit artifacts to a third-party API at all. Point it at your own server.
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field
from typing import Any

ROLES = ("detect", "provision", "patch", "verify")

# Rough lineage buckets, used only to warn when the verifier shares a family
# with the fixer. Substring match on the model id; wrong guesses are harmless.
_FAMILIES = {
    "qwen": ("qwen", "vulnllm", "qwq"),
    "glm": ("glm", "chatglm", "z-ai", "zai"),
    "deepseek": ("deepseek",),
    "kimi": ("kimi", "moonshot"),
    "llama": ("llama", "codellama"),
    "mistral": ("mistral", "codestral", "devstral"),
    "granite": ("granite", "antares"),
    "gemma": ("gemma",),
    "gpt": ("gpt-", "o1", "o3", "o4"),
    "claude": ("claude",),
}


def family_of(model: str) -> str:
    m = (model or "").lower()
    for fam, needles in _FAMILIES.items():
        if any(n in m for n in needles):
            return fam
    return "unknown"


class ConfigError(Exception):
    pass


@dataclass
class ModelConfig:
    role: str
    endpoint: str                 # OpenAI-compatible base, e.g. http://host:8000/v1
    model: str
    api_key: str = ""             # resolved at load time; never persisted back
    api_key_env: str = ""
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout_s: int = 300
    extra: dict = field(default_factory=dict)

    @property
    def family(self) -> str:
        return family_of(self.model)

    def masked(self) -> str:
        if not self.api_key:
            return "(no key)"
        return f"{self.api_key[:4]}…{self.api_key[-2:]}" if len(self.api_key) > 8 else "(set)"


@dataclass
class SandboxConfig:
    backend: str = "podman"       # podman | docker | none
    image: str = ""               # blank = use the repo's own devcontainer/Dockerfile
    network: str = "none"         # containers get no network by default
    # TEMPORARY POSTURE — provision pods get bridge network for the first
    # live Struts run so the model can git clone / apt-get / mvn fetch.
    # NO EGRESS ALLOWLIST YET — anything the pod resolves is reachable.
    # The provision loop LOGS every host it touches (kind
    # "provision_egress_host") so we can build a real allowlist from
    # observed data. TIGHTEN TO AN EXPLICIT ALLOWLIST BEFORE UNATTENDED
    # OPERATION. Default stays "none" — every other stage is unchanged.
    provision_network: str = "none"
    cpus: float = 2.0
    memory: str = "4g"
    timeout_s: int = 1800


@dataclass
class PipelineConfig:
    workdir: str = ".patchwing"
    db: str = "patchwing.db"
    max_attempts: int = 3
    max_patch_bytes: int = 65536
    # Fix-writer iterations per finding. After the first patch attempt, if verify
    # returns `different_bug` (i.e. the fix closed the original but exposed the
    # next masked one), the runner may loop up to this many total iterations. 0
    # or 1 means no automatic iteration; the user has to click "iterate once
    # more" from the web UI. The UI honours this cap even in interactive mode.
    max_iterations: int = 1
    # UI mode. "bounded" runs to max_iterations without asking. "after_each"
    # pauses after every iteration and waits for the user to click "iterate once
    # more" (or stop). Stages.py and runner.py never read this — it is a signal
    # to the web control plane only, so the CLI is unaffected.
    iteration_mode: str = "bounded"
    # Definition-A boundary: reproducers stop at the observable violation.
    # Flipping this is not supported; it exists to make the boundary explicit.
    reproducer_scope: str = "definition_a"
    # Per-finding cost ceiling, summed across every seat for the finding's
    # lifetime. Never unbounded: PatchWing runs unattended, and the failure to
    # defend against is a retry loop spending all night, not one costly call.
    # Tokens are always enforced; dollars only when the operator has configured
    # prices, because a bring-your-own-endpoint tool cannot know what an endpoint
    # charges. Set to 0 to disable a limit — deliberately explicit.
    max_tokens_per_finding: int = 1_000_000
    max_usd_per_finding: float = 5.00


@dataclass
class Config:
    models: dict[str, ModelConfig]
    sandbox: SandboxConfig
    pipeline: PipelineConfig
    warnings: list[str] = field(default_factory=list)

    def model(self, role: str) -> ModelConfig:
        if role not in self.models:
            raise ConfigError(
                f"no model configured for role '{role}'.\n"
                f"Add a [models.{role}] section — see patchwing.example.toml."
            )
        return self.models[role]

    def describe(self) -> str:
        lines = ["models:"]
        for role in ROLES:
            m = self.models.get(role)
            if m is None:
                lines.append(f"  {role:<8} (not configured)")
            else:
                lines.append(f"  {role:<8} {m.model}  [{m.family}]  "
                             f"{m.endpoint}  key={m.masked()}")
        lines.append(f"sandbox: {self.sandbox.backend} "
                     f"network={self.sandbox.network} "
                     f"cpus={self.sandbox.cpus} mem={self.sandbox.memory}")
        lines.append(f"pipeline: db={self.pipeline.db} "
                     f"workdir={self.pipeline.workdir} "
                     f"scope={self.pipeline.reproducer_scope}")
        for w in self.warnings:
            lines.append(f"warning: {w}")
        return "\n".join(lines)


def _resolve_key(role: str, raw: dict, warnings: list[str]) -> str:
    env_name = raw.get("api_key_env", "")
    inline = raw.get("api_key", "")

    if env_name:
        # DB `model_config.api_key` is the authoritative store and is merged in
        # AFTER this function runs (server.apply_db_config). An empty env var
        # here does NOT mean "calls will fail" — it means "no env override";
        # the DB row wins. Warning removed accordingly. If the DB also has no
        # key, the model call itself will surface AuthError with the exact
        # missing-key detail, which is a better signal than a preflight guess.
        return os.environ.get(env_name, "")

    if inline:
        endpoint = raw.get("endpoint", "")
        if not _is_local(endpoint):
            warnings.append(
                f"[models.{role}] has an inline api_key for a remote endpoint. "
                f"Use api_key_env instead — do not commit credentials.")
        return inline

    return ""


def _is_local(endpoint: str) -> bool:
    e = (endpoint or "").lower()
    return any(h in e for h in ("localhost", "127.0.0.1", "::1", "0.0.0.0",
                                "host.docker.internal", "host.containers.internal"))


def load(path: str | None = None, *, strict: bool = False) -> Config:
    """
    Load configuration from a TOML file.

    Search order: explicit path → $PATCHWING_CONFIG → ./patchwing.toml.
    With strict=True, warnings become errors.
    """
    candidates = [p for p in (path, os.environ.get("PATCHWING_CONFIG"),
                              "patchwing.toml") if p]
    chosen = next((p for p in candidates if os.path.exists(p)), None)
    if chosen is None:
        raise ConfigError(
            "no config file found.\n"
            f"  looked for: {', '.join(candidates)}\n"
            "  copy patchwing.example.toml to patchwing.toml and edit it."
        )

    with open(chosen, "rb") as fh:
        try:
            raw = tomllib.load(fh)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{chosen}: invalid TOML — {e}") from e

    warnings: list[str] = []
    models: dict[str, ModelConfig] = {}

    for role, section in (raw.get("models") or {}).items():
        if not isinstance(section, dict):
            raise ConfigError(f"[models.{role}] must be a table")
        if role not in ROLES:
            warnings.append(f"[models.{role}] is not a known role "
                            f"({', '.join(ROLES)}) — ignored")
            continue
        endpoint = section.get("endpoint", "").rstrip("/")
        model_id = section.get("model", "")
        if not endpoint or not model_id:
            raise ConfigError(
                f"[models.{role}] needs both 'endpoint' and 'model'")
        if not endpoint.endswith("/v1"):
            warnings.append(
                f"[models.{role}] endpoint '{endpoint}' does not end in /v1 — "
                f"most OpenAI-compatible servers expect it")
        known = {"endpoint", "model", "api_key", "api_key_env", "temperature",
                 "max_tokens", "timeout_s"}
        models[role] = ModelConfig(
            role=role,
            endpoint=endpoint,
            model=model_id,
            api_key=_resolve_key(role, section, warnings),
            api_key_env=section.get("api_key_env", ""),
            temperature=float(section.get("temperature", 0.2)),
            max_tokens=int(section.get("max_tokens", 4096)),
            timeout_s=int(section.get("timeout_s", 300)),
            extra={k: v for k, v in section.items() if k not in known},
        )

    # The design requires an adversarial verifier from a different lineage than
    # the fixer. Same family shares blind spots, so the second opinion is worth
    # much less. Warn rather than refuse — the user may know better.
    p, v = models.get("patch"), models.get("verify")
    if p and v:
        if p.model == v.model:
            warnings.append(
                "verify uses the SAME MODEL as patch — the adversarial check is "
                "close to worthless. Configure a different model family.")
        elif p.family == v.family and p.family != "unknown":
            warnings.append(
                f"verify and patch are both '{p.family}' family — they share "
                f"blind spots. Prefer a different lineage for the verifier.")

    sb_raw = raw.get("sandbox") or {}
    sandbox = SandboxConfig(
        backend=sb_raw.get("backend", "podman"),
        image=sb_raw.get("image", ""),
        network=sb_raw.get("network", "none"),
        provision_network=sb_raw.get("provision_network", "none"),
        cpus=float(sb_raw.get("cpus", 2.0)),
        memory=sb_raw.get("memory", "4g"),
        timeout_s=int(sb_raw.get("timeout_s", 1800)),
    )
    if sandbox.backend not in ("podman", "docker", "none"):
        raise ConfigError(f"[sandbox] backend must be podman, docker or none "
                          f"(got '{sandbox.backend}')")
    if sandbox.backend == "none":
        warnings.append(
            "[sandbox] backend='none' runs untrusted code on the host. "
            "Only do this inside a disposable VM.")
    if sandbox.network != "none":
        warnings.append(
            f"[sandbox] network='{sandbox.network}' gives analysed code network "
            f"access. 'none' is strongly preferred.")

    pl_raw = raw.get("pipeline") or {}
    pipeline = PipelineConfig(
        workdir=pl_raw.get("workdir", ".patchwing"),
        db=pl_raw.get("db", "patchwing.db"),
        max_attempts=int(pl_raw.get("max_attempts", 3)),
        max_patch_bytes=int(pl_raw.get("max_patch_bytes", 65536)),
        max_iterations=int(pl_raw.get("max_iterations", 1)),
        iteration_mode=str(pl_raw.get("iteration_mode", "bounded")),
        reproducer_scope=pl_raw.get("reproducer_scope", "definition_a"),
        max_tokens_per_finding=int(pl_raw.get("max_tokens_per_finding", 1_000_000)),
        max_usd_per_finding=float(pl_raw.get("max_usd_per_finding", 5.00)),
    )
    if pipeline.max_tokens_per_finding < 0 or pipeline.max_usd_per_finding < 0:
        raise ConfigError(
            "pipeline.max_tokens_per_finding and max_usd_per_finding must not be "
            "negative. Use 0 to disable a limit explicitly.")
    if pipeline.max_tokens_per_finding == 0 and pipeline.max_usd_per_finding == 0:
        warnings.append(
            "both per-finding cost ceilings are disabled — an unattended run has "
            "no upper bound on spend")
    if pipeline.reproducer_scope != "definition_a":
        raise ConfigError(
            "pipeline.reproducer_scope must be 'definition_a'. PatchWing produces "
            "exploitability proof — a trigger plus an observable boundary "
            "violation — and nothing beyond it.")

    cfg = Config(models=models, sandbox=sandbox, pipeline=pipeline,
                 warnings=warnings)

    if strict and warnings:
        raise ConfigError("strict mode; warnings:\n  " + "\n  ".join(warnings))
    for w in warnings:
        print(f"config warning: {w}", file=sys.stderr)
    return cfg


def dump_toml(cfg: "Config") -> str:
    """Serialize a Config back to TOML. Writes api_key_env only, never api_key."""
    out=[]
    for role in ROLES:
        m=cfg.models.get(role)
        if not m: continue
        out+=[f"[models.{role}]",f'endpoint = "{m.endpoint}"',f'model = "{m.model}"']
        if m.api_key_env: out.append(f'api_key_env = "{m.api_key_env}"')
        out+=[f"temperature = {m.temperature}",f"max_tokens = {m.max_tokens}",f"timeout_s = {m.timeout_s}",""]
    sb=cfg.sandbox
    out+=["[sandbox]",f'backend = "{sb.backend}"',f'image = "{sb.image}"',f'network = "{sb.network}"',f"cpus = {sb.cpus}",f'memory = "{sb.memory}"',f"timeout_s = {sb.timeout_s}",""]
    pl=cfg.pipeline
    out+=["[pipeline]",f'workdir = "{pl.workdir}"',f'db = "{pl.db}"',f"max_attempts = {pl.max_attempts}",f"max_patch_bytes = {pl.max_patch_bytes}",f"max_iterations = {pl.max_iterations}",f'iteration_mode = "{pl.iteration_mode}"',f'reproducer_scope = "{pl.reproducer_scope}"',""]
    return "\n".join(out)


def save(cfg: "Config", path: str) -> None:
    with open(path,"w",encoding="utf-8") as fh: fh.write(dump_toml(cfg))


def apply_db_overlay(cfg: "Config", db_path: str) -> None:
    """Overlay DB-stored provider config onto the loaded toml config. DB wins.

    Called from both the server's startup AND the CLI's cmd_run so both
    surfaces converge on the DB (edited via the web UI) as the authoritative
    source of provider config. The toml is a fallback shape only.

    Silent no-op if the DB or table is unavailable — the model call itself
    will surface any missing-key detail with exact caller context."""
    import sqlite3, json
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = list(conn.execute("SELECT * FROM model_config"))
        finally:
            conn.close()
    except Exception:
        return
    for r in rows:
        role = r["role"]
        if role not in ROLES:
            continue
        if not r["endpoint"] or not r["model"]:
            continue
        env_name = r["api_key_env"] or ""
        key = r["api_key"] or (os.environ.get(env_name, "") if env_name else "")
        try:
            extra = json.loads(r["extra"] or "{}")
        except Exception:
            extra = {}
        cfg.models[role] = ModelConfig(
            role=role,
            endpoint=r["endpoint"].rstrip("/"),
            model=r["model"],
            api_key=key,
            api_key_env=env_name,
            temperature=float(r["temperature"] or 0.2),
            max_tokens=int(r["max_tokens"] or 4096),
            timeout_s=int(r["timeout_s"] or 300),
            extra=extra,
        )
