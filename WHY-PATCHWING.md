# Why PatchWing

*The short version: finding vulnerabilities stopped being the hard part. Fixing them — with
proof, at the rate they're found — is the bottleneck now, and almost nothing is built for it.
PatchWing is built for that half.*

---

## The bottleneck moved

For a decade, security tooling optimised **discovery**: scanners, fuzzers, SAST, and now AI
that finds novel zero-days faster than any human team. It worked. We are drowning in findings.

Anthropic's own framing of its Project Glasswing effort put a number on it ([Anthropic, *Project
Glasswing: an initial update*](https://www.anthropic.com/research/glasswing-initial-update)): its
Mythos model has identified **10,000+ high/critical severity vulnerabilities**, and **fewer than
1% have been patched** (0.8% at the time of the update). Their conclusion is the whole thesis of
this project:

> Discovering vulnerabilities at scale without remediating them at comparable scale produces
> *a growing list of exposures, not improved security.*

More finding, past a point, makes things **worse** — it's a longer list of live bugs with no
one to close them.

## The economics are lopsided

Put money on both sides of the gap and it stops being a close call.

A breach from a single unpatched vulnerability costs, on average, **$4.99M globally — $11.5M in
the US** ([IBM, *Cost of a Data Breach 2026*](https://www.ibm.com/reports/data-breach)); the
AI-enabled breaches now running one in four cost about **$6M**. The same report names the gap
directly: **only 18% of organisations apply AI to vulnerability *management*** at all — the
finding side is automated, the fixing side still isn't.

Against those numbers, closing a bug is nearly free. These are the **real spends** from this
repo's own runs, not projections:

- The decompress CVE we closed end to end — reproduced, patched, and verified with a byte-exact
  rollback proof — cost **~$1.28** of inference on a hosted Together endpoint (GLM-5.2 at
  $1.40/$4.40 per 1M tokens). On a cheaper model tier that drops to **~4¢**; **self-hosted it is
  ~$0**, just electricity. *(PatchWing logged that run at $0 because the endpoint seat had no
  price configured — the $1.28 is its recorded token count at Together's list rate.)*
- Even our **worst** run — a target we *failed* to close, after eight patch attempts — cost
  **$5.08** before its budget cut it off.
- Both ran under a **$25 per-finding ceiling that was never approached.** The cap is a safety
  rail, not a bill; the most we ever spent on one finding was that failed $5.08.

So the asymmetry is stark: a fix costs **single-digit dollars**; the breach it forecloses
averages **millions** — a gap of hundreds of thousands to one. Closing the queue isn't a virtue
play. On any spreadsheet, it's the cheapest line item in security. The full breakdown, with an
illustrative calculator, is on one page in [The economics](ECONOMICS.md).

## The pressure is now regulatory, not just prudent

As of **11 September 2026**, the EU **Cyber Resilience Act** reporting obligations are in effect
([EU Commission](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)). When a
manufacturer finds a vulnerability in a third-party component, it must **notify that component's
maintainer** — so EU law now *pushes more findings at open-source maintainers*, with **no
corresponding obligation on anyone to supply a fix.** And for an **actively-exploited**
vulnerability the CRA's final-report clock — **due within 14 days of a corrective measure being
available** — turns "a verified, ready-to-merge fix" from a nice-to-have into something with a
**legal deadline attached.**

The remediation gap isn't just a security problem anymore. It's a compliance one, on a calendar.

## Why the patch was never the hard part

It's tempting to think an LLM that writes code solves this. It doesn't — because the scarce
thing was never the patch. A model will write a plausible patch on demand. What's actually
scarce:

- **Evidence.** Nobody merges an AI patch on faith. A diff with no proof it closes the bug is
  noise — and maintainers are already drowning in low-quality AI-generated reports.
- **Reviewer time.** Maintainers are the genuinely scarce resource. If reviewing your fix takes
  longer than ignoring the finding, you've added load to the bottleneck, not removed it.
- **Liability.** If a patch introduces a regression, someone owns it.

So the patch is nearly free. **The product is the evidence.** The governing constraint of the
whole design follows from that: *a PatchWing PR must be cheaper to review than to ignore.*

## Why the existing tools don't cover this

- **Scanners find; they don't fix.** Semgrep, CodeQL, Snyk, Dependabot — all discovery. PatchWing
  treats discovery as an *input*.
- **"Auto-remediation" means version-bumping.** GitLab, Dependabot and friends bump a vulnerable
  dependency **to a fixed version when one already exists.** The ~9,900 unpatched findings (of the
  10,000+ above) are unpatched *in large part because there is no version to bump to* — nobody has
  written the fix yet. That is the gap.
- **The discovery frontier is closed.** The AI systems that find these at scale are largely not
  publicly available, held back over misuse concerns. You can't compete on discovery against
  models you can't obtain. **The fix queue, by contrast, is wide open.** PatchWing is
  *complementary* to the finders, not competitive with them.

## Why it runs inside your perimeter

When Hugging Face was breached by an autonomous AI agent in July 2026 and its team tried to feed
the attack logs to hosted commercial frontier models for analysis, **the models refused** — their
guardrails couldn't tell an attacker building an exploit from a defender detecting one. HF fell
back to a **self-hosted open-weight model (GLM-5.2) inside their own perimeter**
([HF incident disclosure](https://huggingface.co/blog/security-incident-july-2026)). That is
PatchWing's architecture, improvised live by a marquee victim: **no default provider, per-role
endpoints you control, keys that never leave your box, the reproducer sandbox with no network.**
Some enterprises also simply cannot send code and crash artifacts to a third-party API, at any
price.

## What PatchWing actually does

It takes a **known** bug and runs it through a closure pipeline that ends in a package a
maintainer can accept in minutes:

1. **Reproduce** it — a trigger input plus an observable boundary violation, in a disposable
   container, on real code. Demonstrated, not asserted.
2. **Fix** it — a minimal patch, generated against the exact commit, retried against the
   reproducer's own feedback until it actually closes the bug.
3. **Verify** it — apply → the reproducer goes green → **revert → it goes red again**, proving
   the fix is *what* closed the bug. A four-state classifier that never lets a broken harness
   masquerade as a pass. A different-family model as an adversarial second opinion.
4. **Package** it — a portable, offline-verifiable bundle: the diff, the reproducer, the scripts
   to apply/verify/rollback, the full provenance, every hash. Cheaper to check than to ignore.
5. **Hand it to a human.** A machine never signs off its own work.

## The honest boundary

This is a defensive tool and a young one. Reproducers stop at **Definition A** — "the bad
outcome happened" — never a weaponised exploit chain. The container proves a patch closes the
*specific reproducer* and keeps the suite green; it does **not** prove the patch is globally
correct — that's the real open research problem, and it's why the adversarial reviewer and the
human sign-off are load-bearing. For an unvarnished account of what it has and hasn't closed,
including a run that *didn't* work and why, read the [release notes](RELEASE-NOTES.md).

## The name

PatchWing is a deliberate nod to Anthropic's **[Project Glasswing](https://www.anthropic.com/research/glasswing-initial-update)** —
same "wing," opposite job. Glasswing *finds* vulnerabilities; PatchWing *closes* them. The name
stakes out the complementary half of the pipeline the Glasswing numbers exposed (10,000+ found,
under 1% patched), rather than competing on discovery. (The glasswing is also a real butterfly
with transparent wings — a fitting cousin for a tool whose whole point is that you can see
through it and re-verify every claim yourself.)

---

**Nobody is short of findings. Everyone is short of verified fixes.** That's the gap PatchWing
exists to close.

*New here → [Why PatchWing](WHY-PATCHWING.md) · [User Manual](docs/PatchWing-User-Manual.docx) ·
[Tutorial](docs/TUTORIAL.md) · [Worked example](docs/WORKED-EXAMPLE.md) ·
[Release notes](RELEASE-NOTES.md)*
