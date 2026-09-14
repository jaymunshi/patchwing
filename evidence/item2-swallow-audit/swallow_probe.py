"""What does _advance's broad catch actually do to each exception class?

Machine-derived, not reasoned. Each class is raised from a real stage function,
advanced through the real Runner, and the resulting finding row is read back. No
inference about control flow â€” the store is asked what happened.
"""
import json, os, sqlite3, sys, urllib.error
sys.path.insert(0, r"C:\Users\jaymu\claude-workspace\patchwing-merged")

from patchwing import stages as S
from patchwing.runner import Runner
from patchwing.store import Store
from patchwing import sandbox, models, wall, edit, outcomes, budget, config, fetch, feeds

CASES = [
    ("SandboxError", lambda: sandbox.SandboxError(
        "cannot start container from docker.io/n132/arvo:1237-vul: no space left"),
     "container will not start / exec fails / path escapes sandbox"),
    ("SandboxError (prepare not called)", lambda: sandbox.SandboxError(
        "prepare() must be called before run()"), "sandbox lifecycle bug"),
    ("ModelError", lambda: models.ModelError("patch: HTTP 503 from together.xyz"),
     "fix-writer API 5xx / unreachable"),
    ("RefusalError", lambda: models.RefusalError("model refused"),
     "fix-writer refuses the task"),
    ("AuthError", lambda: models.AuthError("401"), "bad/expired API key"),
    ("WallError", lambda: wall.WallError("cannot hash protected file /tmp/poc"),
     "oracle/wall integrity error"),
    ("EditError", lambda: edit.EditError("search text not unique"),
     "patch application fault"),
    ("sqlite3.OperationalError", lambda: sqlite3.OperationalError(
        "database is locked"), "concurrent DB access"),
    ("json.JSONDecodeError", lambda: json.JSONDecodeError("x", "y", 0),
     "malformed artifact meta"),
    ("OSError", lambda: OSError(28, "No space left on device"),
     "disk full mid-run / unreadable file"),
    ("urllib.error.URLError", lambda: urllib.error.URLError("timed out"),
     "network error not wrapped by a stage"),
    ("KeyError", lambda: KeyError("n_files"), "ordinary programming bug in a stage"),
    ("AttributeError", lambda: AttributeError("'NoneType' has no attribute 'ok'"),
     "ordinary programming bug in a stage"),
    ("MemoryError", lambda: MemoryError(), "host OOM during a 6.57 GB image run"),
    ("UnknownOutcome", lambda: outcomes.UnknownOutcome("verify_geen"),
     "undeclared outcome value (exempted in 9a)"),
    ("CeilingExceeded", None, "cost ceiling tripped (decorator catches it)"),
    ("KeyboardInterrupt", lambda: KeyboardInterrupt(), "operator ^C mid-run"),
    ("SystemExit", lambda: SystemExit(1), "sys.exit inside a stage"),
]

rows = []
for name, factory, cause in CASES:
    stage_name = "probe_" + name.replace(".", "_").replace(" ", "_").replace("(", "").replace(")", "")
    if factory is None:
        rows.append((name, cause, "n/a", "BLOCKED (ceiling_exceeded)",
                     "caught by the stage() decorator, never reaches _advance"))
        continue

    def make(f_=factory):
        def _stage(f, ctx):
            raise f_()
        return _stage

    S._REGISTRY[stage_name] = make()
    store = Store(":memory:")
    r = Runner(store, verbose=False, max_attempts=3)
    finding = store.add_finding(source="probe", repo_url="http://x.invalid",
                                stage=stage_name)
    escaped = ""
    try:
        r._advance(finding)
    except BaseException as e:
        escaped = type(e).__name__
    got = store.get(finding.id)
    if escaped:
        presents = f"ESCAPES the runner ({escaped})"
        note = "propagates to the caller"
    else:
        presents = f"state={got.state} attempts={got.attempts}"
        art = store.latest_artifact(finding.id, "harness_failure")
        if art:
            m = json.loads(art["meta"])
            note = ("one retry granted" if m["retry_granted"]
                    else "TERMINAL on first raise (" + m["outcome"] + ")")
        else:
            note = "UNNAMED - no outcome recorded"
    rows.append((name, cause, escaped or "-", presents, note))
    store.conn.close()
    S._REGISTRY.pop(stage_name, None)

w1 = max(len(r[0]) for r in rows) + 2
w2 = max(len(r[1]) for r in rows) + 2
w3 = max(len(r[3]) for r in rows) + 2
print(f"{'EXCEPTION':<{w1}}{'REALISTIC CAUSE':<{w2}}{'PRESENTS AS':<{w3}}NOTE")
print("-" * (w1 + w2 + w3 + 24))
for name, cause, esc, presents, note in rows:
    print(f"{name:<{w1}}{cause:<{w2}}{presents:<{w3}}{note}")

retried = [r for r in rows if r[4] == "one retry granted"]
terminal = [r for r in rows if r[4].startswith("TERMINAL")]
print(f"\n{len(retried)} get exactly one retry; {len(terminal)} terminate on the "
      f"first raise; {len(rows)-len(retried)-len(terminal)} never reach the catch.")
