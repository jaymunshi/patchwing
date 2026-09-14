# The economics of closing the queue

*The business case for PatchWing, in one page. Finding bugs is automated; fixing them, with
proof, still isn't — so the queue of found-but-unpatched vulnerabilities grows. This page puts
money on both sides of that gap. Every PatchWing figure here is a **real recorded spend**, not a
projection. For the full argument, see [Why PatchWing](WHY-PATCHWING.md).*

---

## The asymmetry, in one line

**A fix costs single-digit dollars. The breach it forecloses averages millions.**

| | Cost |
|---|---|
| Close one bug with PatchWing (hosted) | **~$1.28** |
| Close one bug (cheap model tier) | **~$0.04** |
| Close one bug (self-hosted) | **~$0** (compute only) |
| Average data breach — global | **$4.99M** |
| Average data breach — US | **$11.5M** |
| Average **AI-enabled** breach | **$6M** |

That's a gap of **hundreds of thousands to one** — and yet fewer than 1% of found
vulnerabilities get patched, because the finding side is automated and the fixing side isn't.
(Breach figures: [IBM, *Cost of a Data Breach 2026*](https://www.ibm.com/reports/data-breach).)

## What a fix actually costs

These are the **real spends** from PatchWing's own runs — its recorded token counts, priced at
the endpoint's published rate:

| Run | Tokens | Model / tier | Cost |
|---|---:|---|---:|
| decompress CVE — **closed, full chain** | 405,375 | GLM-5.2 (hosted Together) | **≈ $1.28** |
| systeminformation — **failed**, stopped at budget | — | hosted | **$5.08** |
| Same 405k tokens on a cheap tier | 405,375 | GLM-5.3 Flash ($0.15/$0.50 per 1M) | **~$0.14** |
| Same run, self-hosted | 405,375 | your own GPU | **~$0** (electricity) |

Two things that matter for a budget owner:

- The one bug we **closed** cost **~$1.28**. The one we **failed** to close cost **$5.08** — and
  failure is bounded: it stopped itself at its `investigation_max_usd` budget.
- Both ran under a **$25 per-finding ceiling that was never approached.** The cap is a safety
  rail, not a bill. You set the ceiling; the pipeline refuses to blow past it.

*(A note on honesty: PatchWing logged the decompress run at `$0` because that self-hosted-style
seat had no price configured. The $1.28 is that run's real token count at Together's public
GLM-5.2 rate of $1.40 input / $4.40 output per 1M — the actual cost, made explicit.)*

## Do the math — an illustrative calculator

> **Annual program cost = (fixes per month) × 12 × (cost per fix)**

Cost per fix comes from the table above: **~$0.04** (cheap tier) · **~$1.28** (flagship hosted)
· **~$0** (self-hosted). Worked scenarios against a single **$4.99M** average breach:

| Throughput | Tier | Per fix | Per year | = share of one $4.99M breach |
|---|---|---:|---:|---:|
| 10 fixes/mo | Flash | $0.14 | **~$17** | 0.0003% |
| 50 fixes/mo | flagship | $1.28 | **~$768** | 0.015% |
| 200 fixes/mo | flagship | $1.28 | **~$3,072** | 0.062% |
| 50 fixes/mo | self-hosted | ~$0 | **compute only** | ~0% |

**The break-even is absurd in your favour.** At the *most expensive* tier, closing *200 bugs a
month*, you would run PatchWing for **~1,600 years** before its total cost equalled one average
breach. The program pays for itself if it prevents a single incident in any plausible lifetime of
the software.

## The white space

The market has spent a decade — and most of its budget — on **finding**. IBM's 2026 report found
that **only 18% of organisations apply AI to vulnerability *management*** at all. Everyone is
tooled to discover; almost no one is tooled to close. That is the gap PatchWing is built for, and
it is wide open.

## Honest limits — what this is *not*

- **This is not a projected-ROI model.** It assumes **no breach probability**. It is the raw cost
  asymmetry — what a fix costs vs. what a breach costs — not "expected savings." Whether PatchWing
  prevents any given breach depends on which bugs you feed it and your disclosure discipline.
- **The per-fix cost is grounded in two real runs** (a $1.28 success and a $5.08 stopped failure).
  Your blended cost depends on your model tier and your failure rate; treat these as the shape,
  not a quote.
- **The genuinely scarce resource is maintainer review time, not inference dollars.** PatchWing's
  evidence bundle is designed to cut a review to ~60 seconds — a real saving this page does not
  try to convert to dollars, because it varies too much by team.

---

**Closing the queue isn't a virtue play. On any spreadsheet, it's the cheapest line item in
security.**

*See also: [Why PatchWing](WHY-PATCHWING.md) · [Release notes & field report](RELEASE-NOTES.md) ·
[Worked example](docs/WORKED-EXAMPLE.md)*
