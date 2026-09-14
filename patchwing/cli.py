"""Inspect and drive the pipeline. The human-visible surface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .runner import Runner
from .store import STAGES, Store


def _age(ts: float) -> str:
    d = time.time() - ts
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= n:
            return f"{int(d // n)}{unit}"
    return f"{int(d)}s"


def _load_spec(path: str) -> tuple[dict, dict]:
    """Read a target.toml. Returns (finding_fields, spec_blob)."""
    import tomllib
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)

    target = raw.get("target") or {}
    finding = raw.get("finding") or {}
    commands = raw.get("commands") or {}

    # Paths in a spec are relative to the spec file, so a finding can be added
    # from anywhere without the target moving underneath it.
    base = os.path.dirname(os.path.abspath(path))
    target_dir = os.path.abspath(os.path.join(base, target.get("path", ".")))

    spec = {
        "name": target.get("name", os.path.basename(target_dir)),
        "language": target.get("language", ""),
        "path": target.get("path", "."),
        "_target_dir": target_dir,
        "_spec_path": os.path.abspath(path),
        "files": finding.get("files") or [],
        "commands": {k: commands.get(k, "")
                     for k in ("build", "reproduce", "test", "incremental_build")},
        # Carried through verbatim so containerised targets keep mode/image/root/
        # artifact. Without this the sandbox factory cannot tell an in-image
        # target from a checked-out tree.
        "target": dict(target),
        # Carried verbatim: the wall REQUIRES these to be declared and will abort
        # rather than infer. An absent [suite] and an empty one mean different
        # things, so the key's presence is preserved, not just its value.
        "reproducer": {
            **dict(raw.get("reproducer") or {}),
            "origin": "operator_target_toml",  # Rev-6: ingest-authored
        },
        # Carried verbatim. When a run hands the fix-writer the region instead of
        # discovering it, that fact belongs IN the evidence — a package that does
        # not say localization was oracled is claiming more than the run earned.
        # Dropping this section silently would make the strongest caveat the
        # easiest thing to lose.
        **({"oracle": dict(raw["oracle"])} if "oracle" in raw else {}),
        # Per-run context budget knobs the fix-writer view respects. Also
        # editable via the web UI. Absent = defaults (all trace-derived context
        # files included, no size cap).
        **({"fix_writer": dict(raw["fix_writer"])} if "fix_writer" in raw else {}),
        **({"suite": dict(raw["suite"])} if "suite" in raw else {}),
    }
    fields = {
        "source": finding.get("source", "manual"),
        "source_ref": finding.get("source_ref", ""),
        "repo_url": target_dir,
        "cwe": finding.get("cwe", ""),
        "title": finding.get("title", ""),
        "description": (finding.get("description") or "").strip(),
    }
    return fields, spec


def cmd_add(args, store: Store) -> int:
    if args.spec:
        if not os.path.exists(args.spec):
            print(f"spec not found: {args.spec}")
            return 1
        fields, spec = _load_spec(args.spec)
        # explicit flags still win over the spec
        for k, v in (("source", args.source_set), ("source_ref", args.ref),
                     ("cwe", args.cwe), ("title", args.title),
                     ("description", args.description)):
            if v:
                fields[k] = v
        f = store.add_finding(**fields)
        store.add_artifact(f.id, "spec", "ingest", content=json.dumps(spec, indent=1),
                           meta={"spec_path": spec["_spec_path"]})
        print(f"added {f.id}  {f.title or f.source_ref}")
        print(f"  target   : {spec['_target_dir']}")
        print(f"  files    : {', '.join(spec['files']) or '(scan)'}")
        print(f"  reproduce: {spec['commands']['reproduce'] or '(none)'}")
        print(f"  test     : {spec['commands']['test'] or '(none)'}")
        return 0

    if not args.repo:
        print("provide a repo URL/path, or --spec path/to/target.toml")
        return 1
    f = store.add_finding(
        source=args.source, source_ref=args.ref or "", repo_url=args.repo,
        repo_ref=args.branch or "", cwe=args.cwe or "",
        title=args.title or "", description=args.description or "",
    )
    print(f"added {f.id}  {f.title or f.source_ref or f.repo_url}")
    return 0


def cmd_run(args, store: Store) -> int:
    cfg = None
    try:
        from .config import ConfigError, load, apply_db_overlay
        cfg = load(args.config)
        # DB is the authoritative provider store (edited via the web UI);
        # merge it in so CLI and server converge on one source of truth.
        try: apply_db_overlay(cfg, args.db)
        except Exception: pass
    except Exception as e:
        # The pipeline runs without models; stages needing one will block.
        if not args.quiet:
            print(f"(no model config: {e.__class__.__name__}; "
                  f"model-backed stages will block)")
    r = Runner(store, workdir=args.workdir, verbose=not args.quiet, config=cfg)
    n = r.run(limit=args.limit)
    print(f"advanced {n} finding(s)")
    return 0


def cmd_list(args, store: Store) -> int:
    rows = store.list_findings(state=args.state, stage=args.stage, limit=args.limit)
    if not rows:
        print("no findings")
        return 0
    print(f"{'id':<18}{'state':<10}{'stage':<11}{'age':>5}  title")
    print("-" * 78)
    for f in rows:
        print(f"{f.id:<18}{f.state:<10}{f.stage:<11}{_age(f.updated_at):>5}  "
              f"{(f.title or f.source_ref or f.repo_url)[:38]}")
    return 0


def cmd_show(args, store: Store) -> int:
    f = store.get(args.id)
    if f is None:
        print(f"no finding {args.id}")
        return 1
    print(f"{f.id}  [{f.state}] stage={f.stage} attempts={f.attempts}")
    print(f"  repo    : {f.repo_url} {f.repo_ref or ''} @ {f.base_commit or '?'}")
    print(f"  source  : {f.source} {f.source_ref or ''}  cwe={f.cwe or '-'}")
    if f.title:
        print(f"  title   : {f.title}")
    if f.error:
        print(f"  error   : {f.error.strip()[:400]}")

    arts = store.artifacts(f.id)
    print(f"\n  artifacts ({len(arts)}):")
    for a in arts:
        stale = ""
        if a["base_commit"] and f.base_commit and a["base_commit"] != f.base_commit:
            stale = "  ** STALE (repo moved) **"
        print(f"    {a['kind']:<16} {a['stage']:<10} "
              f"{len(a['content'] or ''):>7} chars  {a['model'] or '-'}{stale}")

    print(f"\n  events:")
    for e in store.events(f.id):
        dur = f"{e['duration_s']:.1f}s" if e["duration_s"] else ""
        print(f"    {e['stage']:<10} {e['status']:<10} {dur:>7}  "
              f"{(e['message'] or '')[:60]}")
    return 0


def cmd_status(args, store: Store) -> int:
    counts = store.counts()
    if not counts:
        print("pipeline empty")
        return 0
    total = sum(sum(v.values()) for v in counts.values())
    print(f"{total} finding(s)\n")
    print(f"{'stage':<12}" + "".join(f"{s:>10}" for s in
                                     ("pending", "running", "blocked", "pending_signoff", "done",
                                      "rejected", "failed")))
    print("-" * 72)
    for stg in STAGES:
        row = [counts.get(st, {}).get(stg, 0) for st in
               ("pending", "running", "blocked", "pending_signoff", "done", "rejected", "failed")]
        if any(row):
            print(f"{stg:<12}" + "".join(f"{n:>10}" for n in row))
    return 0


def cmd_config(args, store: Store) -> int:
    """Show what the config actually resolved to, keys masked."""
    from .config import ConfigError, load, apply_db_overlay
    try:
        cfg = load(args.config)
    except ConfigError as e:
        print(f"config error: {e}")
        return 1
    # DB is the authoritative provider store (edited via the web UI);
    # overlay so this diagnostic matches what cmd_run actually sees.
    # NO wrapping except: a lying diagnostic is what this verb exists
    # to prevent — surface any DB-read failure.
    apply_db_overlay(cfg, args.db)
    print(cfg.describe())
    return 0


def cmd_preflight(args, store: Store) -> int:
    """Probe every configured endpoint before committing to a run."""
    from .config import ConfigError, load, apply_db_overlay
    from .models import preflight_all
    try:
        cfg = load(args.config)
    except ConfigError as e:
        print(f"config error: {e}")
        return 1
    # DB is the authoritative provider store (edited via the web UI);
    # overlay so the probe uses the same keys/endpoints cmd_run does.
    # NO wrapping except: a preflight that lies about what it is probing
    # is worse than one that fails loudly.
    apply_db_overlay(cfg, args.db)

    if not cfg.models:
        print("no models configured")
        return 1

    rc = 0
    for r in preflight_all(cfg.models):
        ok = r["reachable"] and r["json_ok"] and r["security_ok"]
        mark = "OK  " if ok else "FAIL"
        print(f"[{mark}] {r['role']:<8} {r['model']}  [{r['family']}]")
        print(f"         {r['endpoint']}  {r['latency_s']}s")
        print(f"         reachable={r['reachable']} json={r['json_ok']} "
              f"security={r['security_ok']}")
        for n in r["notes"]:
            print(f"         ! {n}")
        if not ok:
            rc = 1
    return rc


def cmd_feeds(args, store: Store) -> int:
    from . import feeds
    if args.feeds_cmd == "pull":
        res = feeds.ingest(store, osv_limit=args.osv_limit)
        print(f"\ndone: {res['actionable']} actionable of {res['osv_checked']} checked")
        return 0
    # default: show facets
    fc = feeds.facets(store)
    print(f"advisories : {fc['total']}")
    print(f"exploited  : {fc['exploited']} (CISA KEV)")
    print(f"actionable : {fc['actionable']} (OSS + fix)")
    print(f"ransomware : {fc['ransomware']}")
    print("by category:")
    for cat, n in sorted(fc["by_category"].items(), key=lambda kv: -kv[1]):
        print(f"  {cat:<10} {n}")
    return 0


def cmd_serve(args, store: Store) -> int:
    from .server import serve
    cfg = None
    try:
        from .config import load
        cfg = load(args.config)
    except Exception:
        pass  # UI runs read-only fine without models; runs will block model stages
    store.close()  # the server opens its own per-request connections
    serve(args.db, host=args.host, port=args.port, config=cfg, workdir=args.workdir, config_path=args.config)
    return 0


def cmd_unblock(args, store: Store) -> int:
    r = Runner(store, verbose=False)
    ok = r.unblock(args.id, args.note or "")
    print("requeued" if ok else "not blocked (or not found)")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="patchwing")
    p.add_argument("--db", default="patchwing.db")
    p.add_argument("--workdir", default=".patchwing")
    p.add_argument("--config", help="path to patchwing.toml "
                                    "(default: $PATCHWING_CONFIG or ./patchwing.toml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("config", help="show resolved configuration")
    c.set_defaults(fn=cmd_config)

    pf = sub.add_parser("preflight", help="probe configured model endpoints")
    pf.set_defaults(fn=cmd_preflight)

    sv = sub.add_parser("serve", help="run the web control plane")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8700)
    sv.set_defaults(fn=cmd_serve)

    fe = sub.add_parser("feeds", help="pull / inspect the advisory intake feed")
    fe.add_argument("feeds_cmd", nargs="?", choices=["pull", "stats"], default="stats")
    fe.add_argument("--osv-limit", type=int, default=200,
                    help="how many newest advisories to OSV-enrich per pull")
    fe.set_defaults(fn=cmd_feeds)

    a = sub.add_parser("add", help="add a finding")
    a.add_argument("repo", nargs="?", help="repo URL or path (omit with --spec)")
    a.add_argument("--spec", help="target.toml describing the target and commands")
    a.add_argument("--source", default="manual",
                   choices=["advisory", "semgrep", "fuzz", "manual"])
    a.add_argument("--source-set", dest="source_set",
                   help="override the spec's source")
    a.add_argument("--ref", help="GHSA id, rule id, crash hash")
    a.add_argument("--branch")
    a.add_argument("--cwe")
    a.add_argument("--title")
    a.add_argument("--description")
    a.set_defaults(fn=cmd_add)

    r = sub.add_parser("run", help="advance findings")
    r.add_argument("--limit", type=int)
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(fn=cmd_run)

    l = sub.add_parser("list")
    l.add_argument("--state")
    l.add_argument("--stage")
    l.add_argument("--limit", type=int, default=50)
    l.set_defaults(fn=cmd_list)

    s = sub.add_parser("show")
    s.add_argument("id")
    s.set_defaults(fn=cmd_show)

    st = sub.add_parser("status")
    st.set_defaults(fn=cmd_status)

    u = sub.add_parser("unblock")
    u.add_argument("id")
    u.add_argument("--note")
    u.set_defaults(fn=cmd_unblock)

    args = p.parse_args(argv)
    # `add` takes the repo positionally; normalise for cmd_add
    if args.cmd == "add":
        args.repo = args.repo
    store = Store(args.db)
    try:
        return args.fn(args, store)
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
