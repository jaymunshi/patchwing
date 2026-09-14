# PatchWing tutorial

A practical, end-to-end walk through using PatchWing: install it, point it at your own
inference endpoint, feed it a known bug, and read the evidence bundle it hands back. For what
PatchWing *is* and why, read the [README](../README.md) first. For a real finding shown start
to finish, see [WORKED-EXAMPLE.md](WORKED-EXAMPLE.md).

Everything below is real — the commands, the config keys, the pipeline stages. No invented
flags.

---

## 1. What you're driving

PatchWing takes a **known** bug (an advisory, a Semgrep hit, a fuzzer crash) on code you own
and produces a fix a maintainer can merge in minutes: a reproducer that fails before the fix
and passes after, the patch, the project's suite still green, a byte-exact rollback proof, and
a container anyone can re-run. **The product is the evidence**, not the patch. You stay in the
loop — a machine never signs off its own work.

---

## 2. Install

Zero third-party dependencies — standard library only, **Python 3.11+** (it needs `tomllib`).

```bash
git clone <your-fork-or-clone-url> patchwing
cd patchwing
python -m patchwing.cli --help          # sanity check; no install step
```

State lives in a single SQLite file (`patchwing.db` by default). You can inspect the whole
process at any time without running PatchWing: `sqlite3 patchwing.db`.

---

## 3. Configure — point it at your own endpoint

**There is no default provider.** You point each role at an endpoint you control (self-hosted
vLLM/llama.cpp/Ollama, or a hosted OpenAI-compatible API). **Keys live in the environment,
never in the config file** — the file names an env var, it does not hold the secret.

There are four roles: `detect`, `provision`, `patch`, `verify`. A minimal `patchwing.toml`:

```toml
[models.provision]
endpoint    = "http://localhost:8000/v1"     # your own inference server
model       = "your-model"
api_key_env = "PATCHWING_KEY"                 # names the env var; not the key itself

[models.patch]
endpoint    = "http://localhost:8000/v1"
model       = "your-model"
temperature = 0.2
api_key_env = "PATCHWING_KEY"

[models.verify]
endpoint    = "http://localhost:8000/v1"
model       = "a-different-family-model"      # see note below
temperature = 0.0                             # maximum determinism for the verdict seat
api_key_env = "PATCHWING_KEY"

[sandbox]
backend           = "podman"
network           = "none"                     # the reproducer pod has no network
provision_network = "bridge"                   # only the build phase may fetch deps
cpus              = 2.0
memory            = "2g"

[pipeline]
max_attempts        = 4
max_usd_per_finding = 25.0
max_patch_bytes     = 65536
reproducer_scope    = "definition_a"
```

Then export the key and confirm what resolved:

```bash
export PATCHWING_KEY=...            # the secret lives here, in the environment
python -m patchwing.cli config      # prints each role: model [family] endpoint key=masked
```

**The verify seat should be a different model *family* than patch** — that's what makes the
adversarial second opinion worth anything. `config` prints a `[family]` tag per seat; eyeball
that they differ. (The container decides the verdict either way — the verify model only writes
an advisory opinion — but a same-family reviewer shares the fixer's blind spots.)

**DB overrides the file.** If you set seats through the web **Providers** page (below), those
land in the `model_config` table and take precedence over `patchwing.toml`. The file is the
starting shape; the DB is the live source of truth. Provider presets (OpenAI, Claude/Anthropic,
Together, self-hosted) prefill endpoint + the env-var name for you — never the key.

---

## 4. Preflight — probe before you spend

```bash
python -m patchwing.cli preflight
```

For each configured role this checks: **reachable** (endpoint answers), **json_ok** (returns
parseable structured output), and **security_ok** — whether the endpoint will *engage with a
plainly defensive security prompt* instead of refusing it. That third check is the one that
matters: a guardrailed endpoint that refuses "help me fix this vulnerability" is useless here,
and you want to learn that at startup, not three hours into a batch. Non-zero exit if any role
fails, so it drops into CI.

---

## 5. Add a finding and run it

```bash
python -m patchwing.cli add https://github.com/org/proj \
    --source advisory --ref GHSA-xxxx-1111 --cwe CWE-22 \
    --title "Path traversal in archive extractor"

python -m patchwing.cli run              # advance everything that is ready
python -m patchwing.cli run --limit 1    # advance one step (good while learning)

python -m patchwing.cli status           # stage × state matrix
python -m patchwing.cli list --state blocked
python -m patchwing.cli show <id>        # artifacts, events, staleness for one finding
python -m patchwing.cli unblock <id> --note "reviewed"
```

A finding walks the pipeline strictly forward:

```
ingest → localize → provision → reproduce → patch → verify → package → review
```

`run` advances each ready finding; stages that need a model but have none **block with a
reason** rather than failing, so you can see the shape before committing a key. A `verify`
rejection is terminal for that attempt — the finding stops and waits for you (that's the
"machine never signs off" rule). The recursive retrying happens *inside* the patch stage (see
§7), not by the runner re-queuing rejects.

---

## 6. Advisory findings with no upstream fix commit

Sometimes `localize` can't resolve an upstream fix commit (the advisory's linked commit is
wrong, or there simply isn't one). The finding blocks at `localize`. You then hand it two
things through the web API (both accepted only at `stage=localize`; draft-spec additionally
requires a non-ARVO finding):

**Target spec** — which file(s) hold the flaw and how to run the target:

```bash
curl -b cookie -X POST http://127.0.0.1:8700/api/finding/<id>/target-spec \
  -H 'Content-Type: application/json' -d '{
    "files": ["lib/extract.js"],
    "reproducer_kind": "http"
  }'
```

**Draft spec** — the HTTP evidence rule the classifier uses to call red vs green (for an
HTTP-shaped reproducer). The `http` block needs `method`, `endpoint_path_norm` (starts with
`/`), `expected_status_red`, and a non-empty `evidence_rules` list:

```bash
curl -b cookie -X POST http://127.0.0.1:8700/api/finding/<id>/draft-spec \
  -H 'Content-Type: application/json' -d '{
    "method": "GET",
    "endpoint_path_norm": "/extract",
    "expected_status_red": 200,
    "evidence_rules": [
      {"kind": "side_channel_flag", "name": "path_traversal_pwned", "pattern": "True"}
    ],
    "preferred_template": "nodejs-18-official"
  }'
```

`preferred_template` picks the pod base image (run `GET /api/templates` to see what's
verified). Then `run` again — `localize` picks up your spec and advances to `provision`, which
clones the target, builds it, and authors a reproducer that fires the flaw.

---

## 7. Turn on the recursive fixer

By default the patch stage takes one shot. The stronger mode is a **closed investigation
loop**: the model proposes a fix, the harness applies + builds + runs the reproducer, and if
it's still red it feeds the new trace back and the model tries again — up to a budget. It's the
right default for anything non-trivial, because nobody writes the fix in one shot.

It reads from the finding's spec `[fix_writer]` block:

```json
"fix_writer": {
  "investigation_mode": true,
  "investigation_max_turns": 40,
  "investigation_max_usd": 5.0,
  "investigation_max_recursion_depth": 2
}
```

- `investigation_mode` — off by default; turn it on to get the loop.
- `investigation_max_turns` / `investigation_max_usd` — the loop stops at whichever it hits
  first. Set the dollar cap as the real limit and give turns plenty of headroom.
- `investigation_max_recursion_depth` — bounds child investigations spawned when a patch
  surfaces a *different* bug than the one you started on.

Bias the loop toward **patch early, then iterate on the reproducer's feedback** — reading the
reproducer and proposing a candidate fix teaches it more than reading the whole tree.

---

## 8. Read the result

When a finding reaches `review`, `package` has assembled a portable, offline-verifiable
**evidence bundle**. A complete real one ships in this repo:

> [`examples/decompress-CVE-2026-10732-evidence-bundle/`](../examples/decompress-CVE-2026-10732-evidence-bundle/)

Its own `README.md` maps every file. The three scripts a maintainer cares about:

- **`apply.sh`** — applies the patch (`patch.diff`, a standard git-apply-ready unified diff) to
  a checkout. This is the fix, in the form you'd merge.
- **`verify.sh`** — fires the reproducer against the patched target and asserts it's **green**
  (no sanitizer marker / the evidence rule no longer trips). Kind-aware (sanitizer vs HTTP).
- **`rollback.sh`** — reverts the patch so you can confirm the bug comes **back** (red again).
  Reverting is what proves the fix is *what* closed the bug, not a coincidence.

**A maintainer verifies in ~60 seconds:** fire the reproducer (red) → `apply.sh` + rebuild →
`verify.sh` (green) → `rollback.sh` + rebuild → red again. Every claim in `evidence.md` is
backed by a file whose sha256 is listed in `hashes.txt`, and `manifest.json` carries the
provenance (which model sat in which seat, the §6a hash triple, the four-state readings, the
chain-proof flag). See [WORKED-EXAMPLE.md](WORKED-EXAMPLE.md) for a full read-through.

---

## 9. The web control plane

There's a web UI at **http://127.0.0.1:8700** (start it with `python -m patchwing.cli serve`;
it's admin-authenticated — on first start it seeds a default **`admin` / `admin`** login).
There is no in-UI password change yet, so **keep it bound to `127.0.0.1`** (the default) and treat
it as a localhost dev tool. It mirrors the CLI:

- **Dashboard** — every finding, its stage/state, and drill-down into events and artifacts.
- **Providers** (`/providers`) — set the per-role model seats (endpoint / model / env-var
  name / temperature); writes the `model_config` table. Presets for OpenAI, Claude, Together,
  and self-hosted prefill everything but the key.
- **Finding detail** — the full timeline, the prompts the model saw, its responses, the
  verdict readings, and a bundle download.

Bind it to `127.0.0.1` unless you specifically need LAN access; it's a single-tenant dev tool.

---

*Next: [WORKED-EXAMPLE.md](WORKED-EXAMPLE.md) walks the shipped decompress bundle end to end.*
