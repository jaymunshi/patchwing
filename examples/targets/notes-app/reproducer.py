#!/usr/bin/env python3
"""
Definition-A reproducer for CWE-22 in NoteStore.read_note.

Trigger: a note name containing `..` path segments.
Observable boundary violation: content from OUTSIDE base_dir is returned.

It stops there. It demonstrates that the containment boundary can be crossed —
not what an attacker would go on to read on a real system.

Exit codes follow the convention PatchWing expects of every reproducer:
    non-zero  the vulnerability reproduces (expected BEFORE the patch)
    zero      the boundary held (expected AFTER the patch)
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from notes.store import NoteStore  # noqa: E402

SENTINEL = "SECRET-OUTSIDE-BASEDIR-a41f9c"


def main() -> int:
    root = tempfile.mkdtemp(prefix="patchwing-repro-")
    base = os.path.join(root, "notes")
    os.makedirs(base, exist_ok=True)

    # A file the store must never be able to reach: a sibling of base_dir.
    with open(os.path.join(root, "secret.txt"), "w", encoding="utf-8") as fh:
        fh.write(SENTINEL)

    store = NoteStore(base)
    store.write_note("hello.txt", "a legitimate note")

    traversal = os.path.join("..", "secret.txt")
    try:
        content = store.read_note(traversal)
    except Exception as e:
        print(f"PASS: boundary held — read_note({traversal!r}) refused: "
              f"{type(e).__name__}: {e}")
        return 0

    if SENTINEL in content:
        print(f"FAIL: boundary violated — read_note({traversal!r}) returned "
              f"content from outside base_dir:")
        print(f"      {content.strip()[:80]}")
        return 1

    print("PASS: boundary held — no out-of-base content returned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
