# The evidence package

PatchWing's output is not "a patch." It is a **portable, offline-verifiable evidence bundle** —
the thing a maintainer actually reads to decide whether to merge. This document is the anatomy
of that bundle: what's in it, what each part proves, and how a reviewer checks the whole claim
without trusting PatchWing at all.

A complete, real bundle ships in this repo and is referenced throughout:

> [`examples/decompress-CVE-2026-10732-evidence-bundle/`](../examples/decompress-CVE-2026-10732-evidence-bundle/)
> — the closure of a real Zip-Slip (CVE-2026-10732), 126 files. Its own `README.md` maps every one.

For the run that produced it, see [`WORKED-EXAMPLE.md`](WORKED-EXAMPLE.md). To generate a bundle
yourself, see [`TUTORIAL.md`](TUTORIAL.md).

---

## The governing constraint

> **A PatchWing PR must be cheaper to review than to ignore.**

Everything in the bundle serves that. The patch is nearly free — a model writes a plausible one
on demand. What's scarce is the *evidence* that the patch closes the specific bug, that removing
it brings the bug back, and that nothing was fudged along the way. So the bundle is built to be
checked in about a minute, by a stranger, trusting none of it.

`package` assembles the bundle by **reading the store only** — no re-run happens at bundle time,
no model is called, no container is touched. Every claim in the human-readable writeup is backed
by a file whose sha256 is listed, and the bundle tarball is reproducible (timestamps derived
from the finding, members sorted).

---

## What's in it

### The fix, in the form you'd merge

| File | What it is |
|---|---|
| `patch.diff` | Unified diff, `git apply`-ready. |
| `patch.searchreplace.json` | The model's raw SEARCH/REPLACE edit blocks, before they became a diff. |
| `apply.sh` | **Hash-guarded** patch application: refuses to apply unless the target file matches the recorded pre-patch sha256, and refuses to *finish* unless the post-patch file matches the recorded after-patch sha256. No silent drift. |

### The proof it closes the bug

| File | What it proves |
|---|---|
| `reproducer/` (`poc`, `run.sh`) | The exact reproducer input and its one-line invocation — byte-identical to what was frozen before any patch existed. |
| `verify.sh` | Fires the reproducer against the patched target and asserts **green** (kind-aware: sanitizer marker for native findings, the HTTP evidence rule for server findings). |
| `rollback.sh` | Reverts the patch so you can confirm the bug comes **back red** — proving the fix is *what* closed it, not a coincidence. |
| `verdicts/` | The container's four-state readings at each leg. |
| `container.txt` | The exact image the reproducer runs in. |

### The provenance — who did what, and what it cost

| File | What it carries |
|---|---|
| `manifest.json` | The machine-readable spine: which model sat in which seat, the **§6a hash triple** (`before_patch` / `after_patch` / `after_revert`), the four-state readings, and the `chain_proved` flag. |
| `hashes.txt` | sha256 of every member — recompute them; nothing was edited after the fact. |
| `finding.json` | The full dashboard-parity dump: every event, artifact, and reading. |
| `prompts/` | The captured model prompt(s), system + user body (the fixer's, at minimum). |
| `responses/` | Every raw model response, verbatim. |
| `spend/` (`spend.jsonl`, `spend_prior.jsonl`) | Each model call's token and USD cost, per seat. (`spend_prior.jsonl` may be empty when there was no prior run.) |
| `traces/investigation.jsonl` | The per-turn trace of the recursive fixer — the tool calls it made. Empty/flat when the finding was closed in a single patch attempt rather than the investigation loop. |
| `process-log.jsonl` | The full stage-by-stage timeline. |

### The honest second opinion

| File | What it is |
|---|---|
| `advisory/` · `review_advisory` | A **different model's** opinion on the patch — stamped clearly as *an opinion, not a verdict*, printed **with the exact model, endpoint, temperature and independence caveat that produced it**. It did not and cannot change the pass/fail the container decided. When it says "concerns," read them. |

---

## How the trust actually works

Two mechanisms make a "green" mean something. Both are recorded in the bundle so you can audit
them.

**The four-state classifier.** The verdict is read from the reproducer's **output**, never its
exit code. A reading is one of `confirmed_red`, `confirmed_green`, `different_bug`, or
`harness_fault`. The last two are neither red nor green and never fold into either — a timeout,
a broken build, or an exit-1-with-no-marker is *absence*, not a verdict, and is marked
`patch_evaluated: false`. This is what stops "the harness glitched" from being reported as "the
bug is fixed."

**The chain: red → apply → green → revert → red again.** All in one persistent container:

1. hash the target file (`before_patch`);
2. apply the fix, hash again (`after_patch`);
3. re-hash the *frozen* reproducer files — any change **voids the run** (the "wall");
4. build, run the reproducer → must be `confirmed_green`;
5. revert to the exact pre-patch bytes, hash (`after_revert`), assert
   `after_revert == before_patch` **byte-for-byte** (the *§6a hash triple*); rebuild, run → must
   read `confirmed_red` **again**.

The target outcome, `verify_green_rollback_red`, is recorded in `verdicts/0001-verify.json` and
`finding.json` (and `manifest.json` carries the same result as `chain_proof.chain_proved: true`
plus the rollback hash-triple). Note that
**rollback is evidence, not a gate**: if the revert doesn't come back red, the patch is *not*
rejected — the container already ruled green — it's recorded honestly as
`verify_green_rollback_not_red`, which indicts the undo mechanism or the oracle, not the fix.

---

## Verify it yourself in ~60 seconds

Trusting none of the above:

1. **Fire the reproducer on unpatched code** → it goes **red**. The bug is demonstrated, not asserted.
2. **`apply.sh <checkout>`** + rebuild → the patch lands (hash-guarded).
3. **`verify.sh`** → the reproducer now reads **green** — closed.
4. **`rollback.sh <checkout>`** + rebuild → the reproducer goes **red again** — proving the patch
   is what closed it.

Then recompute `hashes.txt` and read `manifest.json`'s provenance. If any claim in `evidence.md`
isn't backed by a hashed file in the archive, that's a bug in the bundle — report it.

---

*See also: [`WORKED-EXAMPLE.md`](WORKED-EXAMPLE.md) (a full read-through of the shipped bundle),
[`TUTORIAL.md`](TUTORIAL.md) (produce your own), and the [main README](../README.md).*
