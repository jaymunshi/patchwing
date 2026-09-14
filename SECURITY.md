# Security Policy

## Scope

PatchWing is a **defensive-only** bug-fixing tool. It fixes defects in code the operator owns
or is authorised to fix, and its reproducers stop at **Definition A** — an observable boundary
violation ("the bad outcome happened"), never a weaponised exploit chain. It does not scan,
hunt, or probe third-party systems.

The CVEs referenced in the documentation and `examples/` are **already public and already
fixed upstream**. They are evaluation targets, not disclosures, and contain no novel exploit
information.

## Reporting a vulnerability in PatchWing itself

If you find a security issue **in PatchWing's own code** (for example, a sandbox escape, a way
to make the verifier certify a patch that does not close the bug, or a way to poison the
evidence bundle), please report it privately:

- **Do not** open a public GitHub issue for it.
- Email the maintainer at the address published on the repository owner's GitHub profile, or
  use GitHub's private **"Report a vulnerability"** advisory flow on this repository.
- Include the version/commit, a minimal reproduction, and the impact you observed.

You will get an acknowledgement, and a fix or a written decision, as fast as a single
maintainer reasonably can. Please allow time to remediate before any public disclosure.

## Handling the tool's outputs safely

- A PatchWing evidence bundle may embed a **reproducer** that triggers the very bug it
  documents. Treat reproducer inputs as untrusted: run them only inside the sandbox the bundle
  names (`network: none`), never against production.
- Every "green" verdict is decided by the **container**, not by the model that wrote the patch.
  A patch verified green proves the *frozen reproducer* is closed and the suite stays green —
  **not** that the patch is globally correct. Read the advisory-review section of each bundle,
  and have a human review before merging anything.
