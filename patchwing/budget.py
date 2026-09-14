"""Per-finding cost ceiling — the hard stop.

PatchWing runs unattended. The failure being defended against is not one expensive
call; it is a retry loop quietly spending 100K tokens to produce twenty lines, three
times over, across three seats, at 3am. So the ceiling is **per finding, across every
seat**, not per call.

Design notes worth knowing:

**Tokens are the primary unit, dollars are optional.** PatchWing is bring-your-own-
endpoint: a local Ollama costs nothing, a Together key costs something, and an
in-house vLLM costs something we cannot see. We therefore always enforce a token
ceiling, and additionally enforce a dollar ceiling only when the operator has told
us the prices. A tool that can only bound spend when it knows the price list would be
unbounded exactly where it matters — someone else's endpoint.

**Spend is recorded as artifacts, not a new table.** The artifacts table is already
the audit trail, and this avoids a schema migration. Each entry carries the seat,
the model, and the token counts, so the evidence package can show where the money
went rather than a single opaque number.

**The check happens before AND after each call.** Before, so a call that obviously
cannot fit is never made; after, because the only way to know what a call cost is to
make it. A single call may therefore overshoot the ceiling — it cannot be prevented,
only reported — but the *next* one will not happen.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# Bounded by default. A measured CVE-Bench advisory task used ~140K tokens end to
# end; a three-seat run with retries can plausibly reach 3-4x that. One million
# leaves generous headroom while still stopping a runaway loop within minutes.
DEFAULT_MAX_TOKENS = 1_000_000
DEFAULT_MAX_USD = 5.00

SPEND_KIND = "spend"
# Rows demoted from SPEND_KIND when a human requeues a blocked/failed finding.
# spent() only sums SPEND_KIND, so the counter reads "current attempt only"
# while the historical rows survive for cost-per-fix audits (added when the
# per-finding cumulative counter kept tripping the ceiling across human
# reset-and-retry cycles). Do NOT demote spend rows on automated pipeline
# retries; the ceiling's unattended-runaway guard depends on those still
# accumulating.
SPEND_PRIOR_KIND = "spend_prior"


class CeilingExceeded(Exception):
    """Raised when a finding has spent its allowance. Terminal for the run."""

    def __init__(self, finding_id: str, spent: "Spend", ceiling: "Ceiling"):
        self.finding_id = finding_id
        self.spent = spent
        self.ceiling = ceiling
        super().__init__(str(self))

    def __str__(self) -> str:
        return (f"cost ceiling exceeded for {self.finding_id}: "
                f"{self.spent.describe()} against {self.ceiling.describe()}")


@dataclass(frozen=True)
class Ceiling:
    max_tokens: int = DEFAULT_MAX_TOKENS
    max_usd: float = DEFAULT_MAX_USD

    @classmethod
    def from_config(cls, cfg) -> "Ceiling":
        p = getattr(cfg, "pipeline", None)
        return cls(
            max_tokens=int(getattr(p, "max_tokens_per_finding", DEFAULT_MAX_TOKENS)
                           or DEFAULT_MAX_TOKENS),
            max_usd=float(getattr(p, "max_usd_per_finding", DEFAULT_MAX_USD)
                          or DEFAULT_MAX_USD),
        )

    def describe(self) -> str:
        return f"ceiling {self.max_tokens:,} tokens / ${self.max_usd:.2f}"


META_KEY = "cost_ceiling"


def load_ceiling(store, cfg=None) -> Ceiling:
    """Operator setting from the panel wins over the config file, which wins over
    the default — the same precedence the provider panel already uses, so there is
    one place to look when a number surprises you.

    Stored in the existing `meta` key-value table on purpose: exposing a ceiling in
    the UI must not require a schema migration.
    """
    base = Ceiling.from_config(cfg) if cfg is not None else Ceiling()
    try:
        row = store.conn.execute(
            "SELECT value FROM meta WHERE key = ?", (META_KEY,)).fetchone()
    except Exception:
        return base
    if not row or not row[0]:
        return base
    try:
        d = json.loads(row[0])
        return Ceiling(
            max_tokens=int(d.get("max_tokens", base.max_tokens)),
            max_usd=float(d.get("max_usd", base.max_usd)),
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        return base


def save_ceiling(store, max_tokens: int, max_usd: float) -> Ceiling:
    """Persist an operator-set ceiling. Rejects negatives; 0 disables a limit."""
    max_tokens = int(max_tokens)
    max_usd = float(max_usd)
    if max_tokens < 0 or max_usd < 0:
        raise ValueError("ceilings must not be negative; use 0 to disable a limit")
    store.conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
        (META_KEY, json.dumps({"max_tokens": max_tokens, "max_usd": max_usd})))
    store.conn.commit()
    return Ceiling(max_tokens=max_tokens, max_usd=max_usd)


@dataclass
class Spend:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd: float = 0.0
    calls: int = 0
    priced: bool = True          # False once any call had no price configured

    @property
    def tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def describe(self) -> str:
        d = f"{self.tokens:,} tokens in {self.calls} call(s)"
        if self.usd:
            d += f", ${self.usd:.4f}"
            if not self.priced:
                d += " (partial — some seats have no price configured)"
        return d

    def as_dict(self) -> dict:
        return {"prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "tokens": self.tokens, "usd": round(self.usd, 6),
                "calls": self.calls, "fully_priced": self.priced}


def price_of(model_cfg) -> tuple[float, float] | None:
    """(usd per 1M input, usd per 1M output) if the operator configured them.

    Prices live beside the endpoint because only the operator knows what their
    endpoint charges — we must never ship a price table that goes stale.
    """
    extra = getattr(model_cfg, "extra", None) or {}
    pin = extra.get("price_in_per_1m", getattr(model_cfg, "price_in_per_1m", None))
    pout = extra.get("price_out_per_1m", getattr(model_cfg, "price_out_per_1m", None))
    if pin is None and pout is None:
        return None
    try:
        return float(pin or 0.0), float(pout or 0.0)
    except (TypeError, ValueError):
        return None


def _price_lookup_from_db(store, model: str) -> tuple[float, float] | None:
    """Read live per-1M USD pricing for `model` from DB model_config.
    Returns (pin, pout) or None. Enables read-side reprice so historical
    spend rows with priced=false get correct USD when the operator
    populated pricing after the fact."""
    if not model:
        return None
    try:
        row = store.conn.execute(
            "SELECT extra FROM model_config WHERE model=? LIMIT 1",
            (model,)).fetchone()
    except Exception:
        return None
    if not row or not row["extra"]:
        return None
    try:
        e = json.loads(row["extra"])
    except Exception:
        return None
    pin = e.get("price_in_per_1m")
    pout = e.get("price_out_per_1m")
    if pin is None and pout is None:
        return None
    try:
        return float(pin or 0.0), float(pout or 0.0)
    except (TypeError, ValueError):
        return None


def _reprice_meta(meta: dict, store) -> dict:
    """Return meta with usd/priced recomputed from live DB pricing IF the
    row was written unpriced. Rows already priced=true keep their write-time
    USD (fast path). Adds `priced_at_read=True` so audits can distinguish."""
    if not isinstance(meta, dict):
        return meta
    if meta.get("priced"):
        return meta
    pins = _price_lookup_from_db(store, meta.get("model", ""))
    if not pins:
        return meta
    pin, pout = pins
    pt = int(meta.get("prompt_tokens", 0) or 0)
    ct = int(meta.get("completion_tokens", 0) or 0)
    usd = (pt / 1e6) * pin + (ct / 1e6) * pout
    return {**meta, "usd": round(usd, 6), "priced": True, "priced_at_read": True}


def per_call_spend(store, finding_id: str) -> list[dict]:
    """Every spend row for a finding, live-priced. For budget guards + audit.

    Returns list of dicts with:
      id, stage, created_at, seat, model, endpoint,
      prompt_tokens, completion_tokens, usd, priced, priced_at_read (opt)

    A budget guard checking a per-finding token or USD ceiling should read
    this rather than raw store rows — it's the one place read-side reprice
    is applied uniformly."""
    out = []
    for row in store.artifacts(finding_id, SPEND_KIND):
        try:
            m = json.loads(row["meta"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        m = _reprice_meta(m, store)
        m["id"] = row["id"]
        m["stage"] = row["stage"]
        m["created_at"] = row["created_at"]
        out.append(m)
    return out


def spent(store, finding_id: str) -> Spend:
    """Total spend for a finding across every seat, for its whole lifetime.
    Uses read-side reprice so historical unpriced rows get current DB pricing."""
    s = Spend()
    for row in store.artifacts(finding_id, SPEND_KIND):
        try:
            m = json.loads(row["meta"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        m = _reprice_meta(m, store)
        s.prompt_tokens += int(m.get("prompt_tokens", 0) or 0)
        s.completion_tokens += int(m.get("completion_tokens", 0) or 0)
        s.usd += float(m.get("usd", 0.0) or 0.0)
        s.calls += 1
        if not m.get("priced", False):
            s.priced = False
    return s


def total_lifetime(store, finding_id: str) -> Spend:
    """Sum spend + spend_prior + all descendant children (via parent_finding_id).

    This is the DISPLAY total for the dashboard. Includes:
      - live spend rows against this finding (ceiling metering also uses these)
      - spend_prior rows demoted on human requeue (see server.py:start_run)
      - live + prior spend of every child spawned via different_bug recursion,
        recursively.

    Semantics differ from spent(): spent() is "current attempt only" (feeds the
    ceiling check). total_lifetime() is "everything ever spent under this
    finding-id subtree." If any single call was unpriced (model not in the
    price map), `priced` on the return is False and the dashboard should show
    the USD figure as a partial estimate.
    """
    s = Spend()
    unpriced_call_count = 0

    def _fold_kind(fid: str, kind: str) -> None:
        nonlocal unpriced_call_count
        for row in store.artifacts(fid, kind):
            try:
                m = json.loads(row["meta"] or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            m = _reprice_meta(m, store)
            s.prompt_tokens += int(m.get("prompt_tokens", 0) or 0)
            s.completion_tokens += int(m.get("completion_tokens", 0) or 0)
            s.usd += float(m.get("usd", 0.0) or 0.0)
            s.calls += 1
            if not m.get("priced", False):
                s.priced = False
                unpriced_call_count += 1

    def _walk(fid: str, seen: set) -> None:
        if fid in seen:
            return                          # defensive against parent cycles
        seen.add(fid)
        _fold_kind(fid, SPEND_KIND)
        _fold_kind(fid, SPEND_PRIOR_KIND)
        # Descend into children (found via parent_finding_id column).
        try:
            children = store.conn.execute(
                "SELECT id FROM findings WHERE parent_finding_id = ?",
                (fid,)).fetchall()
        except Exception:
            children = []                   # column may not exist on old DBs
        for row in children:
            _walk(row[0], seen)

    _walk(finding_id, set())
    # Expose the unpriced-call count as an attribute so the dashboard can say
    # exactly HOW partial the estimate is ("~$X — 3 call(s) unpriced").
    s.unpriced_calls = unpriced_call_count  # type: ignore[attr-defined]
    return s


def record(store, finding_id: str, seat: str, model_cfg, usage,
           stage_name: str = "") -> Spend:
    """Write one call's cost into the audit trail and return the new total."""
    pin_pout = price_of(model_cfg)
    usd = 0.0
    if pin_pout:
        pin, pout = pin_pout
        usd = (usage.prompt_tokens / 1e6) * pin + (usage.completion_tokens / 1e6) * pout
    meta = {
        "seat": seat,
        "model": getattr(model_cfg, "model", "?"),
        "endpoint": getattr(model_cfg, "endpoint", ""),
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "usd": round(usd, 6),
        "priced": bool(pin_pout),
    }
    store.add_artifact(finding_id, SPEND_KIND, stage_name or seat,
                       "", meta, "", meta["model"])
    return spent(store, finding_id)


TOPUP_KIND = "ceiling_topup"


def topup(store, finding_id: str, tokens: int = 0, usd: float = 0.0,
          actor: str = "human", reason: str = "") -> dict:
    """Grant a finding more budget. A DELIBERATE HUMAN ACTION ONLY.

    The budget is per-finding **lifetime**, not per-attempt. Per-attempt is
    unbounded in aggregate, which destroys the ceiling for the unattended case it
    exists to protect. So the only way a finding gets more allowance is someone
    choosing to give it some, and every grant is recorded separately rather than
    folded into a new total.

    Why separately: cost-per-fix curves are a headline result. A budget that
    silently resets — or one where three top-ups look like one generous ceiling —
    makes that data meaningless. The evidence package must be able to say "started
    at X, was topped up twice, spent Y in total", because "the ceiling was Z" would
    be a different and misleading claim.

    Nothing in the pipeline may call this. It has no automatic caller by design.
    """
    if tokens < 0 or usd < 0:
        raise ValueError("a top-up cannot be negative")
    if not tokens and not usd:
        raise ValueError("a top-up must grant something")
    meta = {"tokens": int(tokens), "usd": float(usd), "actor": actor,
            "reason": reason or "(no reason recorded)"}
    store.add_artifact(finding_id, TOPUP_KIND, "human", "", meta, "", "")
    return meta


def topups(store, finding_id: str) -> list[dict]:
    """Every grant made to this finding, oldest first."""
    out = []
    for row in store.artifacts(finding_id, TOPUP_KIND):
        try:
            out.append(json.loads(row["meta"] or "{}"))
        except (json.JSONDecodeError, TypeError):
            continue
    return out


def effective_ceiling(store, finding_id: str, base: Ceiling) -> Ceiling:
    """The base ceiling plus any human top-ups. Never resets, only extends."""
    ts = topups(store, finding_id)
    if not ts:
        return base
    return Ceiling(
        # A disabled limit (0) stays disabled; topping up an unlimited budget is
        # meaningless rather than an error.
        max_tokens=(base.max_tokens + sum(int(t.get("tokens", 0)) for t in ts)
                    if base.max_tokens else 0),
        max_usd=(base.max_usd + sum(float(t.get("usd", 0.0)) for t in ts)
                 if base.max_usd else 0.0),
    )


def check(store, finding_id: str, ceiling: Ceiling) -> Spend:
    """Raise CeilingExceeded if this finding has spent its allowance.

    A ceiling of 0 means the operator disabled that limit explicitly; it must not
    be read as "zero allowance", which would halt every run immediately.
    """
    ceiling = effective_ceiling(store, finding_id, ceiling)
    s = spent(store, finding_id)
    if ceiling.max_tokens and s.tokens >= ceiling.max_tokens:
        raise CeilingExceeded(finding_id, s, ceiling)
    if ceiling.max_usd and s.usd >= ceiling.max_usd:
        raise CeilingExceeded(finding_id, s, ceiling)
    return s


def remaining(store, finding_id: str, ceiling: Ceiling) -> dict:
    s = spent(store, finding_id)
    return {
        "tokens": max(0, ceiling.max_tokens - s.tokens),
        "usd": max(0.0, ceiling.max_usd - s.usd) if ceiling.max_usd else None,
        "spent": s.as_dict(),
        "ceiling": {"max_tokens": ceiling.max_tokens, "max_usd": ceiling.max_usd},
    }


class Metered:
    """Wraps a Client so every call is checked against the ceiling and recorded.

    The wrapper exists so stages never have to remember to account. A stage that
    forgets to record spend is a stage that runs unbounded, so the accounting is
    attached to the client rather than left to each call site.
    """

    def __init__(self, client, store, finding_id: str, seat: str,
                 ceiling: Ceiling, stage_name: str = ""):
        self._c = client
        self._store = store
        self._fid = finding_id
        self._seat = seat
        self._ceiling = ceiling
        self._stage = stage_name

    @property
    def cfg(self):
        return self._c.cfg

    def _wrap(self, method, *a, **kw):
        check(self._store, self._fid, self._ceiling)      # before
        before = (self._c.usage.prompt_tokens, self._c.usage.completion_tokens)
        try:
            return method(*a, **kw)
        finally:
            from .models import Usage
            delta = Usage(
                prompt_tokens=self._c.usage.prompt_tokens - before[0],
                completion_tokens=self._c.usage.completion_tokens - before[1],
            )
            if delta.total:
                record(self._store, self._fid, self._seat, self._c.cfg, delta,
                       self._stage)

    def chat(self, *a, **kw):
        return self._wrap(self._c.chat, *a, **kw)

    def chat_json(self, *a, **kw):
        return self._wrap(self._c.chat_json, *a, **kw)

    def __getattr__(self, name):
        return getattr(self._c, name)
