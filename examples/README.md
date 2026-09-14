# Examples

Real, runnable walkthroughs. Output shown here is actual output, not illustrative.

---

## 1. Five minutes, no models

The pipeline runs without any model configured — stages that need one block with
a reason. Useful for seeing the shape of the thing before you commit an API key.

```bash
python -m patchwing.cli --db demo.db add https://github.com/example/proj \
    --source advisory --ref GHSA-xxxx-1111 --cwe CWE-787 \
    --title "Heap overflow in parser"

python -m patchwing.cli --db demo.db add https://github.com/example/other \
    --source fuzz --ref crash-9a3f --title "AFL crash in lexer"

python -m patchwing.cli --db demo.db add https://github.com/example/bad
```

```
added 9761c0b54b1e4a56  Heap overflow in parser
added 5bca7c96e7a44373  AFL crash in lexer
added 3f16802a3dd54587  https://github.com/example/bad
```

Now advance everything that's ready:

```bash
python -m patchwing.cli --db demo.db run
```

```
  9761c0b54b1e4a56 ingest → localize
  9761c0b54b1e4a56 localize: blocked — localize not implemented
  5bca7c96e7a44373 ingest → localize
  5bca7c96e7a44373 localize: blocked — localize not implemented
  3f16802a3dd54587 rejected — no description, CWE, or source reference — nothing to localize from
advanced 5 finding(s)
```

Note the third one. It was **rejected at ingest**, not failed: a finding with no
description, CWE, or source reference gives the localizer nothing to work from,
so it is cheaper to drop it than to spend model calls discovering that.

```bash
python -m patchwing.cli --db demo.db status
```

```
3 finding(s)

stage          pending   running   blocked      done  rejected    failed
------------------------------------------------------------------------
ingest               0         0         0         0         1         0
localize             0         0         2         0         0         0
```

---

## 2. Inspecting one finding

```bash
python -m patchwing.cli --db demo.db show 9761c0b54b1e4a56
```

```
9761c0b54b1e4a56  [blocked] stage=localize attempts=0
  repo    : https://github.com/example/proj  @ aaaa111
  source  : advisory GHSA-xxxx-1111  cwe=CWE-787
  title   : Heap overflow in parser
  error   : localize not implemented

  artifacts (1):
    patch            patch           29 chars  glm-5.2

  events:
    ingest     created             Heap overflow in parser
    ingest     ok                  accepted
    localize   blocked             localize not implemented
```

Everything is also plain SQLite, so you never depend on this CLI:

```bash
sqlite3 demo.db "SELECT stage, status, message FROM events ORDER BY created_at;"
```

---

## 3. Staleness — why patches are never rebased

Every artifact records the commit it was generated against. If the repository
moves while a finding sits in a review queue, the patch is **stale by
definition** and the stage regenerates it rather than attempting a rebase.

```python
from patchwing.store import Store

s = Store("demo.db")
f = s.list_findings()[0]
s.update(f.id, base_commit="aaaa111")
s.add_artifact(f.id, "patch", "patch", content="--- a/x.c\n+++ b/x.c",
               base_commit="aaaa111", model="glm-5.2")

s.is_stale(f.id, "patch", "aaaa111")   # False — repo hasn't moved
s.is_stale(f.id, "patch", "bbbb222")   # True  — regenerate
s.is_stale(f.id, "reproducer", "aaaa111")  # True — never generated
```

`show` marks stale artifacts inline with `** STALE (repo moved) **`.

---

## 4. Configuring models

```bash
cp patchwing.example.toml patchwing.toml
$EDITOR patchwing.toml
export PATCHWING_PATCH_KEY=...
python -m patchwing.cli config
```

`config` prints what actually resolved, with keys masked:

```
models:
  detect   UCSB-SURFI/VulnLLM-R-7B  [qwen]  http://localhost:8000/v1  key=(no key)
  patch    glm-5.2  [glm]  https://api.vendor.com/v1  key=sk-t…56
  verify   deepseek-v4-pro  [deepseek]  https://api.vendor.com/v1  key=sk-t…99
sandbox: podman network=none cpus=2.0 mem=4g
pipeline: db=patchwing.db workdir=.patchwing scope=definition_a
```

Two ready-made starting points in this directory:

- **`local-only.toml`** — everything inside your perimeter, nothing leaves.
- **`hosted-fixer.toml`** — local detection and localization, one outbound call
  for the fixer. The common shape.

---

## 5. Preflight before you spend anything

```bash
python -m patchwing.cli preflight
```

Checks each endpoint for reachability, structured-output adherence, and whether
it will engage with a plainly defensive security question:

```
[OK  ] detect   UCSB-SURFI/VulnLLM-R-7B  [qwen]
         http://localhost:8000/v1  1.4s
         reachable=True json=True security=True
[FAIL] patch    some-guardrailed-model  [gpt]
         https://api.vendor.com/v1  0.9s
         reachable=True json=True security=False
         ! REFUSED a benign defensive-security question — this endpoint is
           unsuitable for security work.
```

That last case is the one worth caring about. It is exactly what stopped Hugging
Face's blue team in July 2026: commercial frontier models refused to analyse real
attack logs because guardrails cannot distinguish an attacker building an exploit
from a defender detecting one. Finding out at startup costs nothing; finding out
three hours into a campaign is expensive.

Exit code is non-zero if any role fails, so it drops straight into CI.

---

## 6. Misconfigurations PatchWing complains about

Deliberate, because each one silently degrades results rather than breaking:

```toml
[models.patch]
model = "glm-5.2"
[models.verify]
model = "glm-5.2"        # → "verify uses the SAME MODEL as patch"
```

```toml
[models.verify]
model = "chatglm-4"      # → "verify and patch are both 'glm' family —
                         #    they share blind spots"
```

```toml
[models.patch]
endpoint = "https://api.vendor.com/v1"
api_key = "sk-live-..."  # → "do not commit credentials" (use api_key_env)
```

```toml
[sandbox]
network = "bridge"       # → "gives analysed code network access"
backend = "none"         # → "runs untrusted code on the host"
```

And one that is a hard error rather than a warning:

```toml
[pipeline]
reproducer_scope = "definition_b"
# ConfigError: PatchWing produces exploitability proof — a trigger plus an
# observable boundary violation — and nothing beyond it.
```
