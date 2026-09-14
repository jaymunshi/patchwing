# What `runner._advance`'s broad catch swallows

*Item 2 of the 1237 stretch. **Enumeration only — nothing was rewritten.** Jay decides
what gets promoted out of the catch.*

Generated 1 August 2026. Raw probe output: `evidence/item2-swallow-audit/probe-results.txt`.

---

## The catch

```python
# patchwing/runner.py:66
try:
    result = fn(f, self.ctx)
except stages.outcomes_mod.UnknownOutcome:
    raise                      # narrow exemption added in §9a
except Exception:
    tb = traceback.format_exc(limit=6)
    self.store.update(f.id, state=STATE_PENDING,
                      attempts=f.attempts + 1, error=tb)
    self.store.log(f.id, f.stage, "error", tb, time.time() - started)
    self._say(f"  {f.id} {f.stage}: raised — will retry")
    return
```

Everything that is not `UnknownOutcome` becomes **`STATE_PENDING`, `attempts+1`** —
a retry — and after `max_attempts` (default 3) becomes `STATE_FAILED` carrying a
traceback in `error`.

## Method

Two independent passes, because either alone is the kind of local-signal reading
that has already failed twice here:

1. **What it presents as** — machine-derived. Each exception class was raised from a
   real stage function, advanced through the real `Runner`, and the finding row read
   back from the store. Not reasoned about; observed.
2. **Whether it can reach the catch** — every call site that can raise it in
   `stages.py`, checked against the enclosing `try`. Line numbers cited so this is
   re-checkable rather than assertable.

## The enumeration

`REACHABLE` = there is at least one unwrapped call site in a normal run.

| Exception | Realistic cause in a 1237 run | Reachable? | Presents as |
|---|---|---|---|
| **`SandboxError`** | container will not start; exec fails; 6.57 GB image pull/space; path escapes sandbox | **YES** — `reproduce` L727/737/752, `verify` L1082/1083/1118/1123/1166/1189/1191, `_wsb` L785. Only `patch`'s image read (L919) is wrapped | **retry** |
| **`sqlite3.OperationalError`** | `database is locked` — concurrent store access | **YES** — every `ctx.store.*` call in every stage is unwrapped | **retry** |
| **`OSError`** | disk full mid-build; unreadable protected file via `wall.check` → `_sha256` | **YES** — `verify` L1089/1197 unwrapped | **retry** |
| **`MemoryError`** | host OOM — 6.57 GB image plus a wireshark build | **YES** — anywhere | **retry** |
| **`json.JSONDecodeError`** | malformed patch-artifact meta | **YES** — `verify` L1053 `json.loads(art["meta"])` is unwrapped (other sites are guarded) | **retry** |
| **`KeyError` / `AttributeError` / `TypeError`** | ordinary programming bug in a stage | **YES** — by construction | **retry** |
| `ModelError` | fix-writer API 5xx / unreachable | **partly** — `patch` wraps it (L979 → `patch_model_call_failed`, a *labelled* retry). `localize`'s `symptom_mod.localize(...)` call is unwrapped | retry |
| `RefusalError` | fix-writer refuses the task | partly — same sites as `ModelError` | retry |
| `AuthError` | bad/expired API key | no from `patch` (L972 → `patch_auth_config_error`, correctly a **fail**); yes from `localize` symptom path | retry |
| `EditError` | patch application fault | **no** — caught at L986 → `patch_did_not_apply` | (retry, labelled) |
| `WallError` | oracle/wall integrity | **no** — raised only by `suite_files`/`freeze`/`freeze_in_sandbox`/`assert_patchable`, all inside a `try` (L789, L899). `check`/`check_in_sandbox`/`harden` do not raise it | retry |
| `urllib.error.URLError` | raw network error | **unlikely** — `models`/`fetch`/`feeds` wrap into their own types; `resolve_fix` returns `{"error": ...}` rather than raising | retry |
| `CeilingExceeded` | cost ceiling tripped | **no** — the `stage()` decorator catches it first | **blocked** (`ceiling_exceeded`) |
| `UnknownOutcome` | undeclared outcome value | n/a | **escapes** (§9a exemption) |
| `KeyboardInterrupt` / `SystemExit` | operator ^C; `sys.exit` in a stage | n/a | **escapes** (not `Exception` subclasses) |

**14 of 18 probed classes present as a retry.** Six are confirmed reachable through
unwrapped call sites.

---

## The finding

> *If any of them read as "flaky stage, retry," that is the timeout/compile collapse
> one layer up.*

They do, and it is the same collapse — with one difference that makes it worse.

The timeout/compile defect fused **absence** ("we ran out of clock, the patch was
never judged") with **judgement** ("the patch is not valid code"). Fixing it meant
splitting one boolean into two outcomes. Here the fusion is wider: **infrastructure
failure, programming bugs, and resource exhaustion all present as one transient**,
and they present it to the component that decides whether to spend another attempt.

Three properties make this load-bearing for 1237 specifically:

1. **A retry is an ACTION, not just a label.** A mislabelled outcome is read wrong
   once. A mis-classed exception causes the runner to rebuild a 6.57 GB wireshark
   image and re-run — up to `max_attempts` times. §8 bounds the *timeout* retry to
   one; this path is not bounded by that work and will still take three.

2. **Retrying cannot fix most of what lands here.** Disk-full, OOM, `database is
   locked`, and every `KeyError` are deterministic at the same ceiling — the same
   shape as the §8 note that "a retry at the same ceiling times out again
   deterministically." A retry that cannot succeed is not a retry; it is three
   copies of one failure.

3. **The terminal state is indistinguishable from a real verdict.** After the
   attempts are spent the finding is `STATE_FAILED` with a traceback in `error`, and
   `outcome` is **absent** — the §9a guard covers `StageResult` paths, and this path
   never constructs one. So the exhaustive closed set has a hole exactly where the
   infrastructure fails, and a run that died because the container would not start
   is shaped like a run that was judged and found wanting.

Point 3 is the one I would not have predicted before probing: **§9a's guarantee stops
at the boundary of the broad catch.** Every terminating path carries a declared
outcome, and this is not a terminating path — it is a way of leaving a stage without
producing a result at all.

## What I am NOT doing

Not rewriting the catch, not adding outcome values for these, not narrowing the
`except`. Enumerated and surfaced, as instructed.

## The decision in front of you

Roughly three tiers, if it helps to frame it:

- **Promote to a hard fail (never retry)** — deterministic at the same ceiling:
  `MemoryError`, `OSError(ENOSPC)`, `KeyError`/`AttributeError`/`TypeError`,
  `json.JSONDecodeError`. Retrying these is guaranteed waste.
- **Promote to a labelled outcome, keep retrying** — genuinely transient:
  `sqlite3.OperationalError` (lock contention), `ModelError` (5xx). These deserve a
  name and a bounded count, not silence.
- **Genuinely ambiguous** — `SandboxError`. "Container would not start" could be a
  transient registry hiccup or a permanent config fault, and the class does not
  distinguish them. This is the one I would want your call on rather than a default,
  and it is also the one most likely to fire on 1237.

A fourth option for all of them: leave the catch alone and have it record an
`outcome` before it retries, so the closed set has no hole even if the policy does
not change. That is the smallest change that removes point 3.
