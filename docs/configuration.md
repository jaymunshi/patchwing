# Configuration reference

PatchWing reads a single TOML file. Search order:

1. `--config <path>`
2. `$PATCHWING_CONFIG`
3. `./patchwing.toml`

Start from `patchwing.example.toml`, or one of the two shapes in `examples/`:
`local-only.toml` (nothing leaves the perimeter) and `hosted-fixer.toml` (local
detection, one outbound call).

Verify what resolved — keys are masked — with:

```bash
python -m patchwing.cli config
```

---

## `[models.<role>]`

Three roles: **`detect`**, **`patch`**, **`verify`**. Each is configured
independently.

| key | type | default | meaning |
|---|---|---|---|
| `endpoint` | string | *required* | OpenAI-compatible base URL, normally ending `/v1` |
| `model` | string | *required* | model id as the server expects it |
| `api_key_env` | string | — | **name of an environment variable** holding the key |
| `api_key` | string | — | inline key; warns for non-local endpoints |
| `temperature` | float | `0.2` | |
| `max_tokens` | int | `4096` | |
| `timeout_s` | int | `300` | per request |

Any server speaking `/v1/chat/completions` works: vLLM, llama.cpp, Ollama,
Together, Moonshot, Z.ai, DeepSeek. Swapping provider is configuration, never
code.

### There is no default provider

PatchWing ships with no provider configured, and that is deliberate. Whatever a
security tool names in its own config reads as an endorsement, and where your
source code and crash artifacts travel is a decision only you can make. Some
buyers will not send either to a third-party API under any terms.

### Keys belong in the environment

`api_key_env` names a variable; PatchWing reads it at load time and never writes
it back. Inline `api_key` is tolerated for local endpoints that ignore auth
anyway, and warns for anything remote — config files end up in version control.

### Why roles are separate

The verifier exists to disagree with the fixer. Models from the same lineage
share blind spots, so a same-family verifier mostly agrees and the check is worth
little. A single global model setting would silently destroy that property the
moment someone swapped providers, so roles are configured independently and
PatchWing warns when it detects a collision:

```
config warning: verify uses the SAME MODEL as patch — the adversarial check is
close to worthless. Configure a different model family.

config warning: verify and patch are both 'glm' family — they share blind
spots. Prefer a different lineage for the verifier.
```

Family detection is substring matching on the model id (`qwen`, `glm`,
`deepseek`, `kimi`, `llama`, `mistral`, `granite`, `gemma`, `gpt`, `claude`).
Unrecognised ids report `unknown` and are never warned about — a wrong guess
here is harmless.

### Choosing models per role

**`detect`** — a small model specialised for vulnerability reasoning beats a
large general one, and runs locally for free. VulnLLM-R-7B (Apache 2.0) is
purpose-built and emits a chain-of-thought explaining *why* something is a bug,
which doubles as provenance.

**`patch`** — the only role that genuinely wants a large model. It decides
whether a candidate is real, then writes the fix and the regression test.

**`verify`** — a different family from `patch`. Temperature `0.0`.

---

## `[sandbox]`

Where untrusted code runs. Findings involve executing attacker-controlled inputs
and freshly generated patches, so this section is a security boundary, not a
performance knob.

| key | type | default | meaning |
|---|---|---|---|
| `backend` | `podman` \| `docker` \| `none` | `podman` | container runtime |
| `image` | string | `""` | blank uses the target repo's own Dockerfile/devcontainer |
| `network` | string | `none` | container network mode |
| `cpus` | float | `2.0` | |
| `memory` | string | `4g` | |
| `timeout_s` | int | `1800` | per sandboxed run |

`network = "none"` is the default and strongly preferred — code under analysis
has no business reaching the network. Anything else warns.

`backend = "none"` runs on the host and warns. Only do it inside a disposable VM
you are prepared to destroy.

Leaving `image` blank is usually right: the project knows how to build itself,
and its own devcontainer is a better environment than anything PatchWing would
guess.

### Containers, not nested VMs

Containers are the isolation unit. Nested virtualization requires the hypervisor
to expose VT-x/AMD-V to the guest, which is unavailable on many developer
machines — notably any Windows host running Hyper-V, where VirtualBox falls back
to a backend that cannot nest. The sandbox sits behind an interface, so a
host-level Firecracker backend remains available where you control the metal.

---

## `[pipeline]`

| key | type | default | meaning |
|---|---|---|---|
| `db` | string | `patchwing.db` | SQLite state file |
| `workdir` | string | `.patchwing` | scratch space for clones and builds |
| `max_attempts` | int | `3` | retries per stage before a finding is parked |
| `max_patch_bytes` | int | `65536` | patches larger than this are rejected |
| `reproducer_scope` | string | `definition_a` | **not configurable** |

`max_patch_bytes` is a review-cost control, not a memory limit. A security fix
that rewrites half a file cannot be reviewed in a few minutes, and a patch that
cannot be reviewed quickly fails PatchWing's whole purpose.

`reproducer_scope` must be `definition_a`. Any other value is a hard error:

```
ConfigError: pipeline.reproducer_scope must be 'definition_a'. PatchWing produces
exploitability proof — a trigger plus an observable boundary violation — and
nothing beyond it.
```

The key exists so the boundary is visible in every deployment's config rather
than buried in documentation.

---

## Preflight

```bash
python -m patchwing.cli preflight
```

Probes every configured role for three things:

1. **Reachable** — endpoint answers, auth accepted, model id exists.
2. **JSON** — returns a valid object for a trivial structured request. Adherence
   varies far more across models than benchmark scores suggest.
3. **Security** — engages with a plainly defensive security question ("why does
   a bounds check before `memcpy` prevent a heap overflow?").

The third check is the one that matters. In July 2026 Hugging Face's blue team
could not use commercial frontier models to analyse a live intrusion, because
guardrails cannot distinguish an attacker building an exploit from a defender
detecting one; they moved to self-hosted open weights instead. PatchWing tests for
that at startup rather than three hours into a campaign.

Non-zero exit if any role fails, so it drops straight into CI.

---

## Strict mode

`load(path, strict=True)` promotes every warning to an error. Recommended for
unattended runs, where a misconfigured verifier silently producing weak results
is worse than a loud failure.
