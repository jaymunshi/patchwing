"""Tests for the per-finding cost ceiling.

The failure being defended against is a retry loop spending all night across three
seats, so the tests exercise accumulation across seats and the hard stop, not just
a single oversized call.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchwing import budget  # noqa: E402
from patchwing.models import Usage  # noqa: E402
from patchwing.store import Store  # noqa: E402


class FakeCfg:
    def __init__(self, model="m", extra=None):
        self.model = model
        self.endpoint = "http://x/v1"
        self.extra = extra or {}
        self.role = "patch"


class BudgetTest(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db)
        self.f = self.store.add_finding(source="manual", repo_url="http://r",
                                        title="t", description="d")

    def tearDown(self):
        self.store.close()
        os.unlink(self.db)

    # -- accounting --------------------------------------------------------

    def test_spend_starts_at_zero(self):
        s = budget.spent(self.store, self.f.id)
        self.assertEqual(s.tokens, 0)
        self.assertEqual(s.calls, 0)

    def test_records_a_single_call(self):
        budget.record(self.store, self.f.id, "patch", FakeCfg(),
                      Usage(prompt_tokens=100, completion_tokens=20))
        s = budget.spent(self.store, self.f.id)
        self.assertEqual(s.prompt_tokens, 100)
        self.assertEqual(s.completion_tokens, 20)
        self.assertEqual(s.tokens, 120)
        self.assertEqual(s.calls, 1)

    def test_sums_across_seats(self):
        """The ceiling is per finding, across every seat — not per call."""
        budget.record(self.store, self.f.id, "reproducer", FakeCfg("a"),
                      Usage(1000, 100))
        budget.record(self.store, self.f.id, "patch", FakeCfg("b"),
                      Usage(2000, 200))
        budget.record(self.store, self.f.id, "reviewer", FakeCfg("c"),
                      Usage(500, 50))
        s = budget.spent(self.store, self.f.id)
        self.assertEqual(s.tokens, 3850)
        self.assertEqual(s.calls, 3)

    def test_spend_is_isolated_per_finding(self):
        g = self.store.add_finding(source="manual", repo_url="http://r2", title="u")
        budget.record(self.store, self.f.id, "patch", FakeCfg(), Usage(9000, 0))
        self.assertEqual(budget.spent(self.store, g.id).tokens, 0)

    # -- pricing -----------------------------------------------------------

    def test_usd_computed_when_prices_configured(self):
        cfg = FakeCfg(extra={"price_in_per_1m": 1.0, "price_out_per_1m": 4.0})
        budget.record(self.store, self.f.id, "patch", cfg,
                      Usage(prompt_tokens=1_000_000, completion_tokens=1_000_000))
        s = budget.spent(self.store, self.f.id)
        self.assertAlmostEqual(s.usd, 5.0, places=6)
        self.assertTrue(s.priced)

    def test_unpriced_endpoint_still_tracks_tokens(self):
        """BYO-endpoint: we cannot know what someone's own server charges."""
        budget.record(self.store, self.f.id, "patch", FakeCfg(), Usage(500, 500))
        s = budget.spent(self.store, self.f.id)
        self.assertEqual(s.tokens, 1000)
        self.assertEqual(s.usd, 0.0)
        self.assertFalse(s.priced, "must flag that the dollar figure is incomplete")

    def test_mixed_priced_and_unpriced_is_flagged(self):
        budget.record(self.store, self.f.id, "patch",
                      FakeCfg(extra={"price_in_per_1m": 1.0}), Usage(1000, 0))
        budget.record(self.store, self.f.id, "reviewer", FakeCfg(), Usage(1000, 0))
        self.assertFalse(budget.spent(self.store, self.f.id).priced)

    # -- the hard stop -----------------------------------------------------

    def test_under_ceiling_passes(self):
        budget.record(self.store, self.f.id, "patch", FakeCfg(), Usage(100, 10))
        budget.check(self.store, self.f.id, budget.Ceiling(max_tokens=1000, max_usd=0))

    def test_token_ceiling_halts(self):
        budget.record(self.store, self.f.id, "patch", FakeCfg(), Usage(900, 200))
        with self.assertRaises(budget.CeilingExceeded):
            budget.check(self.store, self.f.id,
                         budget.Ceiling(max_tokens=1000, max_usd=0))

    def test_usd_ceiling_halts(self):
        cfg = FakeCfg(extra={"price_in_per_1m": 10.0, "price_out_per_1m": 10.0})
        budget.record(self.store, self.f.id, "patch", cfg, Usage(1_000_000, 0))
        with self.assertRaises(budget.CeilingExceeded):
            budget.check(self.store, self.f.id,
                         budget.Ceiling(max_tokens=0, max_usd=5.0))

    def test_accumulation_across_seats_trips_the_ceiling(self):
        """No single call exceeds it; together they do. This is the real case."""
        c = budget.Ceiling(max_tokens=1000, max_usd=0)
        for seat in ("reproducer", "patch", "reviewer"):
            budget.check(self.store, self.f.id, c)   # each passes at the time
            budget.record(self.store, self.f.id, seat, FakeCfg(), Usage(400, 0))
        with self.assertRaises(budget.CeilingExceeded):
            budget.check(self.store, self.f.id, c)

    def test_zero_means_disabled_not_zero_allowance(self):
        budget.record(self.store, self.f.id, "patch", FakeCfg(), Usage(10**9, 0))
        budget.check(self.store, self.f.id,
                     budget.Ceiling(max_tokens=0, max_usd=0))  # must not raise

    def test_exception_carries_spend_and_ceiling(self):
        budget.record(self.store, self.f.id, "patch", FakeCfg(), Usage(2000, 0))
        try:
            budget.check(self.store, self.f.id,
                         budget.Ceiling(max_tokens=1000, max_usd=0))
            self.fail("should have raised")
        except budget.CeilingExceeded as e:
            self.assertEqual(e.spent.tokens, 2000)
            self.assertEqual(e.ceiling.max_tokens, 1000)
            self.assertIn("2,000", str(e))

    # -- the metered wrapper ----------------------------------------------

    def test_metered_records_and_then_halts(self):
        class FakeClient:
            def __init__(self):
                self.cfg = FakeCfg()
                self.usage = Usage()
                self.last_raw_response = "{}"

            def chat(self, messages, **kw):
                self.usage.prompt_tokens += 600
                self.usage.completion_tokens += 100
                return "ok"

        c = FakeClient()
        m = budget.Metered(c, self.store, self.f.id, "patch",
                           budget.Ceiling(max_tokens=1000, max_usd=0))

        # First call: nothing spent yet, so it proceeds and costs 700.
        self.assertEqual(m.chat([]), "ok")
        self.assertEqual(budget.spent(self.store, self.f.id).tokens, 700)

        # Second: 700 < 1000 at check time, so it is allowed and OVERSHOOTS to
        # 1400. A call's cost is only knowable after making it — the ceiling
        # bounds the loop, it cannot bound one call.
        self.assertEqual(m.chat([]), "ok")
        self.assertEqual(budget.spent(self.store, self.f.id).tokens, 1400)

        # Third: refused before it is made. This is the property that matters.
        with self.assertRaises(budget.CeilingExceeded):
            m.chat([])
        self.assertEqual(budget.spent(self.store, self.f.id).tokens, 1400,
                         "a refused call must not add spend")

    def test_metered_records_even_when_the_call_raises(self):
        """A call that errors after burning tokens must still be accounted."""
        class Boom:
            def __init__(self):
                self.cfg = FakeCfg()
                self.usage = Usage()
                self.last_raw_response = "{}"

            def chat(self, messages, **kw):
                self.usage.prompt_tokens += 500
                raise RuntimeError("truncated")

        m = budget.Metered(Boom(), self.store, self.f.id, "patch",
                           budget.Ceiling(max_tokens=10_000, max_usd=0))
        with self.assertRaises(RuntimeError):
            m.chat([])
        self.assertEqual(budget.spent(self.store, self.f.id).tokens, 500)

    def test_remaining_reports_headroom(self):
        budget.record(self.store, self.f.id, "patch", FakeCfg(), Usage(300, 0))
        r = budget.remaining(self.store, self.f.id,
                             budget.Ceiling(max_tokens=1000, max_usd=0))
        self.assertEqual(r["tokens"], 700)
        self.assertEqual(r["spent"]["tokens"], 300)




class TopupTest(unittest.TestCase):
    """Lifetime budget: never resets, only extends, and only by human action."""

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db)
        self.f = self.store.add_finding(source="manual", repo_url="http://r", title="t")

    def tearDown(self):
        self.store.close()
        os.unlink(self.db)

    def test_topup_extends_rather_than_resets(self):
        base = budget.Ceiling(max_tokens=1000, max_usd=0)
        budget.record(self.store, self.f.id, "patch", FakeCfg(), Usage(1200, 0))
        with self.assertRaises(budget.CeilingExceeded):
            budget.check(self.store, self.f.id, base)
        budget.topup(self.store, self.f.id, tokens=1000, reason="operator judged it worth continuing")
        budget.check(self.store, self.f.id, base)          # 1200 < 1000+1000
        self.assertEqual(budget.spent(self.store, self.f.id).tokens, 1200,
                         "spend must NOT be reset by a top-up")

    def test_topups_accumulate_and_are_listed_separately(self):
        budget.topup(self.store, self.f.id, tokens=500, reason="a")
        budget.topup(self.store, self.f.id, tokens=250, usd=1.0, reason="b")
        ts = budget.topups(self.store, self.f.id)
        self.assertEqual([t["tokens"] for t in ts], [500, 250])
        self.assertEqual([t["reason"] for t in ts], ["a", "b"])
        eff = budget.effective_ceiling(self.store, self.f.id,
                                       budget.Ceiling(max_tokens=1000, max_usd=5.0))
        self.assertEqual(eff.max_tokens, 1750)
        self.assertAlmostEqual(eff.max_usd, 6.0)

    def test_topup_records_actor_and_reason(self):
        budget.topup(self.store, self.f.id, tokens=1, actor="jay", reason="why")
        t = budget.topups(self.store, self.f.id)[0]
        self.assertEqual(t["actor"], "jay")
        self.assertEqual(t["reason"], "why")

    def test_topup_rejects_empty_and_negative(self):
        with self.assertRaises(ValueError):
            budget.topup(self.store, self.f.id)
        with self.assertRaises(ValueError):
            budget.topup(self.store, self.f.id, tokens=-5)

    def test_disabled_ceiling_stays_disabled(self):
        budget.topup(self.store, self.f.id, tokens=100)
        eff = budget.effective_ceiling(self.store, self.f.id,
                                       budget.Ceiling(max_tokens=0, max_usd=0))
        self.assertEqual(eff.max_tokens, 0)

    def test_no_automatic_caller_exists(self):
        """The pipeline must never top itself up. Guard against drift."""
        import subprocess
        pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "patchwing")
        hits = []
        for name in os.listdir(pkg):
            if not name.endswith(".py") or name == "budget.py":
                continue
            with open(os.path.join(pkg, name), encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    if "topup(" in line and not line.strip().startswith("#"):
                        hits.append(f"{name}:{i}")
        self.assertEqual(hits, [], f"topup() must have no automatic caller; found {hits}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
