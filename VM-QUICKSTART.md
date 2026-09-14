# PatchWing demo VM — quickstart

A ready-to-run VirtualBox appliance with PatchWing installed and **three real CVEs already
closed**, so you can see it work in a few minutes without installing or configuring anything.

> **What you can do with zero setup:** open the console, inspect the three closed findings and
> their full evidence bundles, download a bundle, and run its `verify.sh` to watch a reproducer
> go **red → green → red** on real code.
>
> **To fix a *new* bug** you bring your own model — PatchWing ships with **no API key** (see
> [Fix a new bug](#fix-a-new-bug)).

---

## Getting the OVA

The demo appliance (~6.3 GB) is **not in this Git repository** — it is too large for GitHub.
**Download it from Google Drive:**

> ⬇ **[PatchWing demo VM — `Patchwing-demo.ova` (6.3 GB)](https://drive.google.com/drive/folders/1WqRAr6ODfFPZUKd4SchAwWLEO854pQiE?usp=sharing)**

Open the folder and download `Patchwing-demo.ova`.

You do **not** need the VM to use PatchWing. The code runs from a plain `git clone` against your
own model (see the [README](README.md)), and the shipped
[example evidence bundle](examples/decompress-CVE-2026-10732-evidence-bundle/) is fully
inspectable and re-runnable offline without it. The VM just lets you watch three already-closed
CVEs with zero setup.

---

## Requirements

- **VirtualBox 7.x** (Oracle VM VirtualBox).
- ~**20 GB** free disk for the imported VM, **4+ vCPU** and **8 GB RAM** recommended
  (podman builds are the heavy part).
- The reproducer sandbox uses **podman**, already installed inside the VM.

## Import

1. VirtualBox → **File → Import Appliance…**
2. Select `Patchwing-demo.ova`, accept the defaults, **Import**.
3. Start the **patchwing** VM. PatchWing's web service auto-starts on boot.

## First boot — change the defaults

This is a **demo** image with **documented default credentials**. Change them before you do
anything real.

- **SSH:** `ubuntu` / `ubuntu`, forwarded to host **`127.0.0.1:2224`**
  ```
  ssh -p 2224 ubuntu@127.0.0.1      # then run: passwd   (change it)
  ```
- **Web console admin:** `admin` / `admin` (seeded on first boot). There is **no in-UI password
  change yet**, so leave the console on **localhost only** — don't forward or expose port 8700
  beyond your own machine.

## Open the web console

The VM uses NAT. Add a port-forward so the console is reachable from your browser:

1. VM **Settings → Network → Adapter 1 → Advanced → Port Forwarding**.
2. Add a rule: **TCP**, Host port **8700**, Guest port **8700** (leave IPs blank).
3. Open **http://localhost:8700**, sign in with `admin` / `admin`.

You'll land on the pipeline console with the findings already there.

## Explore the closed findings (no config needed)

Three findings are marked **done** — each is a real closure with a full evidence bundle:

| Finding | CVE | What it is |
|---|---|---|
| `decompress` Zip-Slip | CVE-2026-10732 | Arbitrary file write via a symlink race in npm `decompress`. |
| `libxml2` use-of-uninitialised | OSS-Fuzz / ARVO-1076 | Native ASan finding in `xmlNextChar`. |
| `vite` `fs.deny` bypass | CVE-2025-31125 | Dev-server file read past the allow-list. |

Click one → you get the full timeline, the patch, the prompts and responses, the four-state
verdict readings, and a **bundle download**. Inside the bundle, `verify.sh` runs the reproducer
against the (still vulnerable) container image and shows it fire:

```
ssh -p 2224 ubuntu@127.0.0.1
bash /path/to/bundle/verify.sh patchwing-provisioned-383fc7940acd4a12
#  -> {"zipslip_pwned":"True", ...}
#  -> VERDICT: RED (http evidence rule matched)
```

Apply the patch to a checkout, rebuild, and re-run to watch it go green — the full
red → green → revert → red chain is recorded in the bundle's `manifest.json`.

## Fix a new bug

PatchWing needs an inference endpoint to reproduce, patch and verify — and it ships with **no
key**, on purpose. Bring your own:

1. Web console → **Providers**.
2. Set the **patch** and **verify** seats: pick a provider preset (OpenAI, Together, self-hosted,
   Claude…), fill in the endpoint + model, and either name an env var for the key or paste it to
   store it locally. **Make `verify` a different model family than `patch`** — that's what makes
   the adversarial second opinion worth anything.
3. **Test (preflight)** each seat.
4. Add a finding and run it. For advisories with no upstream fix commit, use the target-spec +
   draft-spec flow — see the [User Manual](docs/PatchWing-User-Manual.docx) and
   [Tutorial](docs/TUTORIAL.md).

## Notes

- This is a **single-tenant dev VM**. Keep it on your own machine; harden (change creds, don't
  expose the console) before any networked use.
- **No live secret ships** with this image — it contains no working API key.
- New here? Start with [Why PatchWing](WHY-PATCHWING.md), then the
  [User Manual](docs/PatchWing-User-Manual.docx).
