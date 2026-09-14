# PatchWing — release notes & field report

*Dev preview. This is an honest log of what the pipeline did on real findings, what changed
this cycle, where the models fell down, and what to expect if you drive PatchWing with an AI
coding agent. The whole project's thesis is that **the evidence is the product** — so these
notes are held to the same standard: every number below came off a real run, and the failures
are written up in as much detail as the successes.*

---

## TL;DR

- **Three real CVEs are closed end-to-end**, each with a full evidence bundle in the store:
  `decompress` Zip-Slip (CVE-2026-10732), `libxml2` use-of-uninitialised (OSS-Fuzz / ARVO-1076),
  and `vite` `fs.deny` bypass (CVE-2025-31125). Two are sanitizer-agnostic HTTP findings; one is
  a native ASan finding. All three reached the target outcome `verify_green_rollback_red`.
- **The recursive fixer now works for long-lived-server (daemon) targets** — a stale-server bug
  that silently blocked the rollback leg was fixed in *both* rollback paths.
- **A fresh fourth CVE did *not* close** — `systeminformation` command injection
  (CVE-2021-21315). It's written up in full below, because *why* it didn't close is more useful
  than the three that did.
- **If you operate PatchWing through an AI agent, expect the agent's own safety layer to gate
  credential access and sign-off.** See ["Operating with an AI agent"](#operating-with-an-ai-agent).

---

## What works today

| Finding | CVE | Kind | Outcome | Notes |
|---|---|---|---|---|
| `decompress` Zip-Slip (symlink race) | CVE-2026-10732 · CWE-22 | HTTP | ✅ `verify_green_rollback_red` | Root-cause fix: serialise extraction (`Promise.all`→`reduce`). Full bundle shipped in `examples/`. |
| `libxml2` use-of-uninitialised | OSS-Fuzz 1076 · CWE-908 | Sanitizer (ASan) | ✅ `verify_green_rollback_red` | Native C target; exit-77 + DEDUP_TOKEN identity. |
| `vite` `fs.deny` bypass | CVE-2025-31125 | HTTP (daemon) | ✅ `verify_green_rollback_red` | Re-proved this cycle after the daemon-reset fix (see below). |
| `systeminformation` cmd injection | CVE-2021-21315 · CWE-78 | HTTP (daemon) | ⚠️ not closed | 8 patch attempts, 0 green. Detailed post-mortem below. |
| `Apache Struts` RCE | CVE-2017-5638 | HTTP | ⛔ rejected at reproduce | Reproducer wall refused an empty frozen set. |

The shipped example bundle (`examples/decompress-CVE-2026-10732-evidence-bundle/`, 126 files)
is a real closure you can inspect and re-run offline: `apply.sh`, `verify.sh`, `rollback.sh`,
the unified diff, the sha256 manifest, and the full prompt/response/cost provenance.

---

## What changed this cycle

1. **Daemon-reset in the rollback legs (correctness).** A reproducer that starts a long-lived
   server with a "start only if not already running" guard would, on the rollback re-run, reuse
   the **green leg's still-patched server** (same persistent pod) and answer with patched code —
   so the reproducer read green against the reverted tree and the chain could *never* prove for
   a daemon target. Fixed in **both** places the rollback lives:
   - `verify()` stage rollback leg — this is why `vite` re-proved its full chain this cycle;
   - the investigation loop's own rollback (`_apply_and_test_in_pod`) — same bug, previously
     unfixed, which would have made the recursive fixer dig forever on any daemon target.

   The fix kills lingering TCP listeners (`ss`/`pkill`) before the red-again re-run, so the
   reproducer relaunches against the reverted code. HTTP-kind only; a sanitizer reproducer
   spawns-and-exits, so it's a no-op there.

2. **Rollback verdict classification (correctness).** The investigation loop's rollback
   `_classify_repro` call was missing the `duration_s` argument every sibling call site passes,
   so a legitimately-green rollback reading tripped the `total_s < 0.001` "possibly-mocked
   harness" guard and was mislabelled `harness_fault`. Now consistent with the four other sites.

3. **Fixer prompt rebiased toward patch-early (behaviour).** `INVESTIGATION_SYSTEM` previously
   opened with *"INVESTIGATE before you patch … follow the data backward until you have
   identified the ACTUAL root cause."* On a strong model with tool access that produced ~20
   turns of `grep`/`read` before the first patch. Rebiased to: *the cheapest probe is a patch
   attempt; investigate only enough to form a first hypothesis, then propose a fix and iterate
   on the reproducer's feedback; stay inside the target's own source* (don't wander into
   `/proc`, npm caches, `/root`).

4. **Model tiering + a genuinely different-family verifier.** Seats moved to `patch = GLM-5.3`,
   `verify = deepseek-ai/DeepSeek-V4-Pro` (a different family, which finally makes the
   adversarial second opinion real), `provision = GLM-5.2`. See the model notes below.

5. **The recursion budget is money-bound, not turn-bound.** `investigation_max_turns` should be
   set high enough that `investigation_max_usd` is the real limit. See the case study.

---

## Model performance notes (read before you pick seats)

These are field observations, not benchmarks — one operator, a handful of real findings.

**GLM-5.2 (the seat that closed the three greens).** Provision on GLM-5.2 authored working
reproducers and converged reliably (e.g. `decompress` in a modest turn count). The three closed
findings were all fixed with GLM-5.2 in the patch seat, in one-shot mode, on targets where the
reproducer and the natural fix *aligned*.

**GLM-5.3 (the recursive fixer on the fourth finding).** On the `systeminformation` recursive
run, GLM-5.3 authenticated and ran fine, and **provision converged in 28 turns** — but the
**fixer wandered**. Its shortcomings, specifically:

- **Explore-vs-patch ratio was badly skewed.** Across ~85 model calls it made **only 4 actual
  patch attempts** — the rest were `grep`/`read`/`list_dir`. Even after the prompt was rebiased
  to patch-early, it front-loaded exploration.
- **It wandered outside the target.** It read `/proc/1/cmdline`, `/proc/net/tcp`, `/root/.npm/_logs`
  (a 56 KB npm log), and issued **duplicate tool calls** it had already made — none of which can
  contain the defect.
- **It didn't reconcile its own two halves.** *Provision* (also GLM) authored a reproducer that
  attacks with a **plain-string** shell-metacharacter payload; the *fixer* (also GLM) wrote the
  **upstream `typeof !== 'string'` guard**, which only blocks *non-string* input. A type guard
  can't stop a string payload — so the model dutifully wrote that same guard **8 times** and it
  never closed the reproducer. The fixer never noticed that the reproducer it could read four
  times contradicted the fix it kept proposing.
- **Raising the budget didn't help** — with turns lifted so money was the real cap, it kept
  exploring and hit ~$5 with **0 chain-proved**.

**The honest attribution:** this was *partly* the target and *partly* the model. The target was
a poor fit — the reproducer and the known upstream fix genuinely target different vectors
(string vs non-string injection), so no clean patch closes that exact reproducer. But a stronger
fixer would have caught the contradiction between the reproducer and its own patch; GLM-5.3, in
this loop, did not. **Takeaways for operators:** (1) make sure your reproducer exercises the
vector your fix will address; (2) bias the fixer to patch-early and cap it by dollars, not
turns; (3) a different-family verifier (we moved to DeepSeek) is worth configuring precisely
because a same-family reviewer shares these blind spots.

---

## Case study: why `systeminformation` (CVE-2021-21315) did not close

A worked failure, because it's the most instructive artifact in this release.

**The bug.** `systeminformation ≤ 5.3.0` has an OS command injection in `lib/internet.js`
(`inetChecksite`/`inetLatency`): a user-controlled value flows into a shell command. The
upstream 5.3.1 fix adds a `typeof … !== 'string'` guard, i.e. it defends the **non-string /
array** vector (`?url[]=…`).

**What the pipeline did, step by step.**
1. `add` → `localize` **blocked** — the advisory's linked "fix commit" resolved to the *wrong
   repo* (`apache/cordova-android`, HTTP 422). This is a real data-quality hazard: advisory feeds
   mis-map fix commits. We supplied an operator **target-spec** + **draft-spec** at
   `stage=localize` (the documented recovery path).
2. `provision` **converged in 28 turns** (~$0.46): cloned `systeminformation@v5.3.0`, wrapped it
   in an Express server, authored a reproducer — which, unprompted, attacked with a **plain
   string** `;touch …` payload (not the array vector).
3. `reproduce` → **`confirmed_red`**: the injection genuinely fired, canary created.
4. `patch` (one-shot, GLM-5.3) → wrote the upstream `typeof` guard → `verify` **rejected**: the
   string payload sails past a non-string guard, so the reproducer stayed red.
5. We enabled the recursive fixer and lifted the turn cap. **8 patch attempts, 0 green, ~$5.08
   total.** The loop wandered (see model notes).

**Root cause of the non-closure:** a **reproducer↔fix vector mismatch**. Provision built a
string-injection reproducer; the natural/upstream fix defends non-string input; the two never
meet. Compounded by the fixer's failure to notice the contradiction and by over-exploration.

**How a maintainer would close it:** either steer provision to author the *array-vector*
reproducer the guard actually closes (matching the real CVE), or write a fix that neutralises
shell metacharacters in the string (which diverges from upstream). Both are legitimate; the
container would prove either. We stopped rather than spend more, because the *pipeline* was
demonstrably working — it **refused to pass a patch that didn't close the reproducer**, which is
the entire point. A rubber-stamp oracle ("the model applied the known CVE fix → pass") would
have shipped a patch that does nothing.

**Numbers for this finding:** 8 patch attempts · 0 chain-proved · ~113 model calls across all
runs · **$5.08** total spend — stopped by the fixer's **$5 investigation budget**
(`investigation_max_usd`), well under the **$25 per-finding ceiling**.

**Cost, in perspective.** $5.08 was our *most expensive* run, and it was a failure. For
contrast, the finding we did close — the decompress CVE in [WORKED-EXAMPLE](docs/WORKED-EXAMPLE.md)
— cost **≈ $1.28** (405,375 tokens at Together's GLM-5.2 rate; PatchWing logged it as $0 because
that seat was unpriced). Neither run came close to the $25 ceiling. Closing a bug costs
single-digit dollars whether it succeeds or fails fast; the ceiling is a rail we never touch.

---

## Operating with an AI agent

This release was built and exercised largely by driving PatchWing through an AI coding agent
(Claude Code). If you do the same, be aware the agent's **own safety layer** — separate from
PatchWing — will gate certain actions. During this cycle it flagged/blocked, among others:

- **Signing a finding off (`cli unblock`)** — refused as *self-approval*. The agent would not
  mark a finding human-signed-off on its own. This actually *aligns* with PatchWing's core rule
  ("a machine never signs off its own work"), enforced one layer up — but it means the human
  must do the sign-off, in the UI or by running `unblock` themselves.
- **Searching the filesystem for API keys** — refused as *credential exploration*. Recovering or
  scrubbing a key had to be done by the human, or via value-blind operations that never read the
  secret into the agent's context.
- **A concurrent monitoring heuristic once mis-flagged** a preflight response as an auth error
  before the key was actually revoked (provider-side caching kept a deleted key alive for ~1–2
  minutes) — a reminder to trust the provider console over a single probe.

None of this is PatchWing behaviour; it's the operating agent's guardrails. The practical
consequence: **credential handling and final sign-off stay with the human**, which is the right
default for a security tool. Plan your runbook around it.

---

## Known issues & limitations

- **`config`/`preflight` require a config file** (`patchwing.toml`) or `--config`; a bare
  `config` with none prints a clear "copy `patchwing.example.toml`" error (working as intended,
  but noted because the tutorial has you create the file in §4).
- **The different-family warning is a false positive after a DB overlay.** `config`/`preflight`
  may print *"verify uses the SAME MODEL as patch"* even when the DB seats are different
  families (the warning is computed from the TOML, not the resolved DB config). **Trust the
  `[family]` tags in the output, not the warning line.**
- **Evidence-bundle `README.md` shipped a sanitizer-kind "verify yourself" snippet** (`arvo run`)
  for an HTTP finding. The actual `verify.sh`/`apply.sh`/`rollback.sh` scripts are correct and
  tested; the bundle's own README template has been corrected in the shipped example.
- **Correctness ≠ test-passing.** The container proves the *frozen reproducer* is closed and the
  suite stays green — **not** that the patch is globally correct. The advisory reviewer exists to
  flag residual surface (it did, on the `decompress` fix). Read it.
- **Single-tenant dev posture.** The web control plane is admin-authed and meant for
  `127.0.0.1`; harden before any networked use. No upstream PR has been submitted anywhere yet —
  the receipts here are self-contained bundles, not merged fixes.

---

*PatchWing — defensive vulnerability closure. Verified fixing, not another scanner. A machine
never signs off its own work.*
