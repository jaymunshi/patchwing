# Worked example — closing a real Zip-Slip (CVE-2026-10732)

This is one PatchWing finding, start to finish, with the **real** artifacts from the run.
Nothing here is illustrative-only: every diff, reading, and hash below is copied from the
evidence bundle shipped at
[`examples/decompress-CVE-2026-10732-evidence-bundle/`](../examples/decompress-CVE-2026-10732-evidence-bundle/).

If you have not read the [main README](../README.md) yet, read it first — it explains *why*
the product is the evidence, not the patch. This document shows *how* one finding produces
that evidence. For the anatomy of the output bundle, see
[`EVIDENCE-PACKAGE.md`](EVIDENCE-PACKAGE.md); to run your own, see [`TUTORIAL.md`](TUTORIAL.md).

| | |
|---|---|
| **Finding** | `383fc7940acd4a12` |
| **Reference** | CVE-2026-10732 · CWE-22 (Zip Slip) |
| **Target** | `decompress` (npm), `kevva/decompress` |
| **Outcome** | `verify_green_rollback_red` — **full chain proved** |
| **Container image** | `patchwing-provisioned-383fc7940acd4a12` |
| **Cost** | 27 model calls · 405,375 tokens (166,720 in / 238,655 out) · all seats `zai-org/GLM-5.2` · **≈ $1.28** at Together's GLM-5.2 list rate ($1.40/$4.40 per 1M). PatchWing logged `$0` for this run because that seat had no price configured — see note below. |

---

## The bug

`decompress` is vulnerable to arbitrary file write via a **symlink race** during archive
extraction. Craft an archive whose entries are processed such that a symlink pointing outside
the output directory is created, and a subsequent file entry is written *through* that symlink
— landing bytes wherever the symlink points.

Root cause is **microtask ordering**. The extractor processes every entry concurrently:

```js
return Promise.all(files.map(x => { /* … write entry x … */ }));
```

`preventWritingThroughSymlink` guards each write by calling `fs.readlink` on the destination.
But under `Promise.all`, the file entry's `readlink` check can run **before** the earlier
symlink entry has finished being created — so the guard sees "not a symlink yet", lets the
write proceed, and the bytes travel through the symlink that materialises a moment later.
This defeats the fix that was shipped for the earlier Zip-Slip, CVE-2020-12265.

---

## Stage by stage

PatchWing carries every finding through the same fixed pipeline:
`ingest → localize → provision → reproduce → patch → verify → package → review`.

### 1. ingest / localize
The advisory is registered as a finding and localization narrows to the file that holds the
flaw: `node_modules/decompress/index.js`. (For an advisory with no discoverable upstream fix
commit, the operator attaches a small target spec naming the file — see the TUTORIAL.)

### 2. reproduce — establish the red **and freeze it**
Provision builds a pod that wraps the vulnerable package in a tiny HTTP server, and the model
authors a reproducer that triggers the extraction and reports whether the write escaped. That
reproducer is then **frozen** — 3 files hashed under sha256 *before any patch exists*:

```
make_exploit.js   reproduce.sh   server.js      (3 files, sha256, frozen)
```

Run against the unpatched code, the reproducer reads **`confirmed_red`**:

```
{"status":"extracted","zipslip_pwned":"True","marker_content":"pwned"}
```

The escape happened. This reading establishes the pristine crash identity everything after is
measured against.

### 3. patch — the fix
The fix-writer (here `GLM-5.2`) is handed the frozen reproducer and the localized file, and
returns a minimal diff. It serialises extraction so each entry is fully written **before** the
next entry's safety checks run — which means the symlink exists by the time the file entry's
`readlink` guard fires:

```diff
--- a/opt/zipslip-target/node_modules/decompress/index.js
+++ b/opt/zipslip-target/node_modules/decompress/index.js
@@ -73,7 +73,7 @@
 		return files;
 	}
 
-	return Promise.all(files.map(x => {
+	return files.reduce((promise, x) => promise.then(() => {
 		const dest = path.join(output, x.path);
 		const mode = x.mode & ~process.umask();
 		const now = new Date();
@@ -125,7 +125,7 @@
 			})
 			.then(() => x.type === 'file' && fsP.utimes(dest, now, x.mtime))
 			.then(() => x);
-	}));
+	}), Promise.resolve()).then(() => files);
 });
```

A `Promise.all(files.map(…))` fan-out becomes a `reduce`-chained sequential run. Two lines
changed; the ordering race is gone.

### 4. verify — the chain: red → green → revert → red-again
This is the load-bearing step, and it all happens **inside one persistent container** so
nothing but the patch changes between legs.

| leg | what runs | reading |
|---|---|---|
| **patched** | apply diff, rebuild, run frozen reproducer | **`confirmed_green`** |
| **rollback** | revert to exact pre-patch bytes, rebuild, run reproducer again | **`confirmed_red`** |

Patched, the reproducer output flips to a clean refusal:

```
{"status":"error","error":"Refusing to write into a symlink","zipslip_pwned":"False"}
```

Then the patch is reverted and the reproducer fires **red again**, proving the fix is *what*
closed the bug — not some incidental change to the tree. The revert is verified byte-exact by
the **§6a hash triple** on the patched file:

```
before_patch   8829ae54…
after_patch    9029a6d8…
after_revert   8829ae54…      ← after_revert == before_patch, byte for byte
wall: 3 reproducer files, sha256, intact throughout
outcome: verify_green_rollback_red
```

The reproducer files' hashes are re-checked at every leg — a "green" obtained by quietly
weakening the test would void the run.

### 5. package
Everything above is assembled into a portable, offline-verifiable evidence bundle — the thing
a maintainer actually reviews. Its full contents are documented in
[`EVIDENCE-PACKAGE.md`](EVIDENCE-PACKAGE.md); the real one is shipped at
[`examples/decompress-CVE-2026-10732-evidence-bundle/`](../examples/decompress-CVE-2026-10732-evidence-bundle/).
Highlights:

- `patch.diff` — the fix, git-apply-ready
- `apply.sh` / `rollback.sh` / `verify.sh` — one-command apply, revert, and re-check
- `evidence.md` — the human-readable writeup, every claim backed by a hashed file
- `manifest.json` / `hashes.txt` — machine-readable provenance and per-file sha256
- `reproducer/` — the byte-identical frozen reproducer
- `prompts/`, `responses/`, `spend/`, `traces/` — the full model trail and cost

> **A note on the `$0` in `spend/`.** Every call in `spend.jsonl` records `"usd": 0.0` because
> this run's `zai-org/GLM-5.2` seat had no price configured (`"priced": false`) — expected for a
> self-hosted endpoint, and honest for what PatchWing *knew*. It still ran against Together's
> hosted API, which billed the tokens. Priced at Together's public GLM-5.2 rate ($1.40 input /
> $4.40 output per 1M), the 166,720 input + 238,655 output tokens come to **≈ $1.28** — the real
> cost of closing this CVE. On a cheaper tier (e.g. GLM-5.3 Flash at $0.15/$0.50) it is ~4¢; the
> run stayed far under its **$25 per-finding ceiling**, which was never approached.

Re-check it yourself in ~60 seconds (from the bundle):

```
bash apply.sh <checkout>      # apply the fix
bash verify.sh <checkout>     # reproducer should be GREEN
bash rollback.sh <checkout>   # revert → reproducer RED again
```

---

## The honest caveat

The container proves **this reproducer is closed** and that removing the patch reopens it. It
does **not** prove the patch is globally correct — and the bundle says so plainly. The
advisory reviewer (an opinion, *not* the verdict — the container decides pass/fail) returned
**"concerns"** and flagged residual CWE-22 surface the reproducer never exercises:

- a broken `indexOf`-based path-containment prefix check,
- symlink targets not validated against the output root,
- a residual TOCTOU window between check and write.

Its independence is stamped **WEAK** — the reviewer shared the `GLM` family with the fix-writer,
so their blind spots correlate. That is recorded honestly in the bundle rather than hidden. In
other words: PatchWing shows you a fix that provably closes the reported bug, with everything
you need to review it in minutes — and it is candid about the limits of that proof. The final
call is a human's.

---

*See also: [README](../README.md) · [TUTORIAL](TUTORIAL.md) · [EVIDENCE-PACKAGE](EVIDENCE-PACKAGE.md) · [the real bundle](../examples/decompress-CVE-2026-10732-evidence-bundle/)*
