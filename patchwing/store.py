"""
Persistent state for the PatchWing pipeline.

Everything the pipeline knows lives in one SQLite file. That is a deliberate
choice: the process flow has to be inspectable by a human without running
PatchWing, and `sqlite3 patchwing.db` beats any dashboard we could ship.

Three tables:

  findings   one row per candidate vulnerability. The unit of work.
  artifacts  stage outputs (localization, reproducer, patch, tests, evidence).
             Append-only and versioned, never overwritten.
  events     append-only audit log of every stage transition.

Patches are stored with the commit they were generated against. A patch whose
`base_commit` no longer matches the repo's HEAD is *stale* by definition, which
is how we detect PR-time desync instead of discovering it at merge.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field, fields
from typing import Any, Iterable

SCHEMA_VERSION = 1

# Pipeline stages, in order. A finding advances through these.
STAGES = ["ingest", "localize", "provision", "reproduce", "patch", "verify", "package", "review"]

# Terminal and non-terminal states.
STATE_PENDING = "pending"      # waiting for its next stage
STATE_RUNNING = "running"      # a stage is executing
STATE_BLOCKED = "blocked"      # needs a human decision (broken or missing input)
STATE_PENDING_SIGNOFF = "pending_signoff"  # review-stage terminal, awaiting approve/reject
STATE_DONE = "done"            # made it through review
STATE_REJECTED = "rejected"    # verified as not a real bug, or unfixable
STATE_FAILED = "failed"        # a stage errored out past its retry budget

OPEN_STATES = (STATE_PENDING, STATE_RUNNING)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    source        TEXT NOT NULL,      -- advisory | semgrep | fuzz | manual
    source_ref    TEXT,               -- GHSA id, rule id, crash hash, ...
    repo_url      TEXT NOT NULL,
    repo_ref      TEXT,               -- branch or tag we were asked to fix
    base_commit   TEXT,               -- repo HEAD when this finding was ingested
    cwe           TEXT,
    title         TEXT,
    description   TEXT,
    stage         TEXT NOT NULL,      -- next stage to run
    state         TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    error         TEXT,
    owner         TEXT DEFAULT '',    -- assignee (enterprise multi-user)
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_find_state ON findings(state, stage);
CREATE INDEX IF NOT EXISTS idx_find_repo  ON findings(repo_url);

CREATE TABLE IF NOT EXISTS artifacts (
    id           TEXT PRIMARY KEY,
    finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,       -- localization | reproducer | patch |
                                      -- regression_test | evidence | verdict
    stage        TEXT NOT NULL,
    content      TEXT,
    meta         TEXT,                -- JSON
    base_commit  TEXT,                -- commit this artifact was produced against
    model        TEXT,                -- which model produced it, if any
    created_at   REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_art_finding ON artifacts(finding_id, kind, created_at);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    stage       TEXT,
    status      TEXT,
    message     TEXT,
    duration_s  REAL,
    actor       TEXT DEFAULT 'system',  -- who/what did it (enterprise audit)
    created_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ev_finding ON events(finding_id, created_at);

-- Intake feed: the big watchable list of published advisories, distinct from
-- `findings` (the handful promoted into the pipeline). Deduped by CVE.
CREATE TABLE IF NOT EXISTS advisories (
    cve              TEXT PRIMARY KEY,
    source           TEXT,     -- kev | osv | nvd
    vendor           TEXT,
    product          TEXT,
    title            TEXT,
    description      TEXT,
    category         TEXT,     -- oss | windows | linux | network | apple | app | other
    ecosystem        TEXT,     -- PyPI, npm, Go, ... when OSS
    package          TEXT,
    fixed_version    TEXT,
    repo_url         TEXT,
    exploited        INTEGER DEFAULT 0,   -- in CISA KEV (actively exploited)
    ransomware       INTEGER DEFAULT 0,
    epss             REAL,      -- 0..1 exploit probability
    epss_pct         REAL,      -- percentile
    cvss             REAL,
    severity         TEXT,
    actionable       INTEGER DEFAULT 0,   -- OSS w/ source + known fixed version
    osv_checked      INTEGER DEFAULT 0,   -- has OSV enrichment actually run?
    date_added       TEXT,      -- KEV date added / advisory published
    due_date         TEXT,      -- KEV remediation due (CRA-like clock)
    published        TEXT,
    modified         TEXT,
    first_seen       REAL,      -- when WE first ingested it ("new" indicator)
    updated_at       REAL,
    promoted_finding TEXT       -- finding id, once promoted
);

CREATE INDEX IF NOT EXISTS idx_adv_exploited ON advisories(exploited, epss);
CREATE INDEX IF NOT EXISTS idx_adv_cat  ON advisories(category);
CREATE INDEX IF NOT EXISTS idx_adv_seen ON advisories(first_seen);
CREATE INDEX IF NOT EXISTS idx_adv_act  ON advisories(actionable);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

-- Pod template library. Templates are GLOBAL (no finding_id) — they are
-- cached provision outputs that any future finding can attach to. Each
-- row records what got installed (recipe_json — ordered tool calls from
-- provision.py's PROVISION_TOOLS), the resulting committed image (tag +
-- immutable digest), and how to verify the stack is still alive
-- (verification_cmd + verification_expect regex).
--
-- image_digest is the load-bearing pin. tag can drift (podman tag re-
-- points a tag at any image); digest cannot. Reproduce must verify the
-- digest before attaching so a re-pointed tag can't silently serve a
-- different image than the template row promises.
CREATE TABLE IF NOT EXISTS pod_templates (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    description         TEXT NOT NULL,
    base_image          TEXT NOT NULL,
    image_tag           TEXT NOT NULL,
    image_size_bytes    INTEGER,
    image_digest        TEXT,
    recipe_json         TEXT NOT NULL,
    recipe_turn_count   INTEGER NOT NULL,
    verification_cmd    TEXT NOT NULL,
    verification_expect TEXT NOT NULL,
    cve_class_hint      TEXT,
    builder_version     TEXT NOT NULL,
    created_at          REAL NOT NULL,
    last_verified_at    REAL,
    last_verified_ok    INTEGER,
    last_verified_note  TEXT
);
CREATE INDEX IF NOT EXISTS idx_pt_hint ON pod_templates(cve_class_hint);
"""


def _now() -> float:
    return time.time()


def _id() -> str:
    return uuid.uuid4().hex[:16]


@dataclass
class Finding:
    id: str
    source: str
    repo_url: str
    source_ref: str = ""
    repo_ref: str = ""
    base_commit: str = ""
    cwe: str = ""
    title: str = ""
    description: str = ""
    stage: str = "ingest"
    state: str = STATE_PENDING
    attempts: int = 0
    error: str = ""
    owner: str = ""            # assignee (enterprise multi-user)
    container_id: str = ""     # pod-per-finding lifecycle (change 2)
    parent_finding_id: str = ""  # different_bug recursion parent (Step 2)
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Finding":
        cols = set(row.keys())
        known = {f.name for f in fields(cls)}
        return cls(**{k: row[k] for k in cols if k in known})

    def next_stage(self) -> str | None:
        """The stage that follows the current one, or None at the end."""
        i = STAGES.index(self.stage)
        return STAGES[i + 1] if i + 1 < len(STAGES) else None


class Store:
    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        # Auth tables (users, sessions). Kept in patchwing/auth.py so the
        # whole login story lives in one file. IF NOT EXISTS on every open.
        from . import auth as _auth
        self.conn.executescript(_auth.SCHEMA)
        # lightweight migrations for columns added after a DB was first created
        for table, col, ddl in (
            ("advisories", "osv_checked", "INTEGER DEFAULT 0"),
            ("findings", "owner", "TEXT DEFAULT ''"),
            ("events", "actor", "TEXT DEFAULT 'system'"),
            # Pod-per-finding (change 2): the podman container id that carries
            # this finding across every stage. Populated by reproduce, read by
            # every stage after, cleared on terminal transitions. Empty means
            # no live pod. Podman reporting "no such container" is a distinct
            # signal (see outcomes.POD_LOST_FINDING_TERMINATED).
            ("findings", "container_id", "TEXT DEFAULT ''"),
            # Live timeline: `status` carries coarse outcomes (ok/retry/reject/
            # fail/created). `kind` names the sub-step within a stage
            # (pod_create, sanitizer_read, prompt_assembled, model_call,
            # response, patch_applied, four_state, hash_triple, ...). `meta`
            # is a JSON blob the UI can expand for details (full prompt,
            # response, build tail).
            ("events", "kind", "TEXT DEFAULT ''"),
            ("events", "meta", "TEXT DEFAULT ''"),
            # different_bug recursion (Step 2): when a patch fixes the parent
            # bug but exposes a NEW downstream crash (four_state=different_bug
            # after patch), the investigation spawns a child finding with the
            # new trace and tries to fix it. Child's parent_finding_id points
            # back so the parent's total cost / verdict can aggregate. Empty
            # means top-level. Recursion bounded by
            # [fix_writer].investigation_max_recursion_depth (default 2).
            ("findings", "parent_finding_id", "TEXT DEFAULT ''"),
        ):
            try:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
            except sqlite3.OperationalError:
                pass  # already present
        self.conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    # -- findings ---------------------------------------------------------

    def add_finding(self, **kw: Any) -> Finding:
        f = Finding(id=kw.pop("id", None) or _id(), **kw)
        self.conn.execute(
            "INSERT INTO findings (id, source, source_ref, repo_url, repo_ref,"
            " base_commit, cwe, title, description, stage, state, attempts,"
            " error, owner, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f.id, f.source, f.source_ref, f.repo_url, f.repo_ref, f.base_commit,
             f.cwe, f.title, f.description, f.stage, f.state, f.attempts,
             f.error, f.owner, f.created_at, f.updated_at),
        )
        self.conn.commit()
        self.log(f.id, "ingest", "created", f.title or f.source_ref)
        return f

    def get(self, finding_id: str) -> Finding | None:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return Finding.from_row(row) if row else None

    def claim_next(self, max_attempts: int = 3) -> Finding | None:
        """
        Take the oldest pending finding and mark it running.

        Single-process for now; the UPDATE...WHERE state='pending' guard is what
        makes it safe to add a second worker later without changing callers.
        """
        row = self.conn.execute(
            "SELECT * FROM findings WHERE state = ? AND attempts < ?"
            " ORDER BY created_at LIMIT 1",
            (STATE_PENDING, max_attempts),
        ).fetchone()
        if row is None:
            return None
        cur = self.conn.execute(
            "UPDATE findings SET state = ?, updated_at = ?"
            " WHERE id = ? AND state = ?",
            (STATE_RUNNING, _now(), row["id"], STATE_PENDING),
        )
        self.conn.commit()
        if cur.rowcount == 0:
            return None  # somebody else took it
        return self.get(row["id"])

    def update(self, finding_id: str, **kw: Any) -> None:
        if not kw:
            return
        kw["updated_at"] = _now()
        cols = ", ".join(f"{k} = ?" for k in kw)
        self.conn.execute(
            f"UPDATE findings SET {cols} WHERE id = ?",
            (*kw.values(), finding_id),
        )
        self.conn.commit()

    def list_findings(self, state: str | None = None, stage: str | None = None,
                      limit: int = 100) -> list[Finding]:
        q, params = "SELECT * FROM findings", []
        where = []
        if state:
            where.append("state = ?"); params.append(state)
        if stage:
            where.append("stage = ?"); params.append(stage)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        return [Finding.from_row(r) for r in self.conn.execute(q, params)]

    # -- artifacts --------------------------------------------------------

    def add_artifact(self, finding_id: str, kind: str, stage: str,
                     content: str = "", meta: dict | None = None,
                     base_commit: str = "", model: str = "") -> str:
        aid = _id()
        self.conn.execute(
            "INSERT INTO artifacts (id, finding_id, kind, stage, content, meta,"
            " base_commit, model, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (aid, finding_id, kind, stage, content,
             json.dumps(meta or {}), base_commit, model, _now()),
        )
        self.conn.commit()
        return aid

    def artifacts(self, finding_id: str, kind: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM artifacts WHERE finding_id = ?"
        params: list[Any] = [finding_id]
        if kind:
            q += " AND kind = ?"
            params.append(kind)
        q += " ORDER BY created_at"
        return list(self.conn.execute(q, params))

    def latest_artifact(self, finding_id: str, kind: str) -> sqlite3.Row | None:
        rows = self.artifacts(finding_id, kind)
        return rows[-1] if rows else None

    def is_stale(self, finding_id: str, kind: str, current_commit: str) -> bool:
        """
        True when the newest artifact of this kind was generated against a
        different commit than the repo is on now. This is the PR-time desync
        check: rather than rebasing a stale patch, we regenerate it.
        """
        art = self.latest_artifact(finding_id, kind)
        if art is None:
            return True
        return bool(art["base_commit"]) and art["base_commit"] != current_commit

    # -- events -----------------------------------------------------------

    def log(self, finding_id: str, stage: str, status: str,
            message: str = "", duration_s: float | None = None,
            actor: str = "system",
            kind: str = "", meta: dict | None = None) -> None:
        meta_str = ""
        if meta:
            try:
                meta_str = json.dumps(meta, default=str)[:16000]
            except (TypeError, ValueError):
                meta_str = ""
        self.conn.execute(
            "INSERT INTO events (finding_id, stage, status, message, duration_s,"
            " actor, kind, meta, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (finding_id, stage, status, message[:4000], duration_s, actor,
             kind or "", meta_str, _now()),
        )
        self.conn.commit()

    def emit(self, finding_id: str, stage: str, kind: str,
             message: str = "", meta: dict | None = None,
             duration_s: float | None = None,
             actor: str = "system") -> None:
        """Lightweight substep event for the live timeline.

        `status` defaults to `event` — coarse outcomes (ok/retry/reject/fail)
        still go through `log`. Callers pass a `kind` naming the substep
        (pod_create, sanitizer_read, prompt_assembled, model_call, response,
        four_state, hash_triple, build_start, build_done...) and an optional
        `meta` dict the UI expands for details.

        Intentionally cheap so stages can emit many of these without slowing
        the pipeline.
        """
        self.log(finding_id, stage, "event", message,
                 duration_s=duration_s, actor=actor, kind=kind, meta=meta)

    def events(self, finding_id: str) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM events WHERE finding_id = ? ORDER BY created_at",
            (finding_id,)))

    # -- reporting --------------------------------------------------------

    def counts(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for r in self.conn.execute(
                "SELECT state, stage, COUNT(*) n FROM findings"
                " GROUP BY state, stage"):
            out.setdefault(r["state"], {})[r["stage"]] = r["n"]
        return out

    # --- pod template library --------------------------------------------
    # Templates are GLOBAL (no finding_id). CRUD only — building a template
    # (running the recipe against a fresh pod, committing, verifying) lives
    # in patchwing/template_builder.py; this store just persists the row.

    def add_template(self, *, name: str, description: str,
                     base_image: str, image_tag: str,
                     recipe_json: str, recipe_turn_count: int,
                     verification_cmd: str, verification_expect: str,
                     builder_version: str,
                     image_size_bytes: int | None = None,
                     image_digest: str | None = None,
                     cve_class_hint: str | None = None):
        """Insert a new template row. UNIQUE(name) — a duplicate name
        raises sqlite3.IntegrityError. That's deliberate: rebuilding a
        template with the same name is a REPLACE decision the caller
        makes explicitly (delete old, insert new), not a silent overwrite.
        Returns the PodTemplate object just inserted."""
        from . import templates as _tpl
        tid = _id()
        now = _now()
        self.conn.execute(
            "INSERT INTO pod_templates("
            "id, name, description, base_image, image_tag, "
            "image_size_bytes, image_digest, recipe_json, "
            "recipe_turn_count, verification_cmd, verification_expect, "
            "cve_class_hint, builder_version, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, name, description, base_image, image_tag,
             image_size_bytes, image_digest, recipe_json,
             int(recipe_turn_count), verification_cmd, verification_expect,
             cve_class_hint, builder_version, now))
        self.conn.commit()
        return self.get_template(tid)

    def list_templates(self):
        """All templates, newest first. Returns PodTemplate objects."""
        from . import templates as _tpl
        rows = self.conn.execute(
            "SELECT * FROM pod_templates ORDER BY created_at DESC").fetchall()
        return [_tpl.PodTemplate.from_row(r) for r in rows]

    def get_template(self, id_or_name: str):
        """Look up by id (primary key) OR by name (unique key). Returns
        PodTemplate or None. Two-column lookup because the UI + API code
        naturally use either — a URL carries the id, a spec's
        preferred_template field carries the name."""
        from . import templates as _tpl
        row = self.conn.execute(
            "SELECT * FROM pod_templates WHERE id = ? OR name = ? LIMIT 1",
            (id_or_name, id_or_name)).fetchone()
        return _tpl.PodTemplate.from_row(row) if row else None

    def update_template_verification(self, template_id: str, *,
                                     ok: bool, note: str = "",
                                     ts: float | None = None) -> None:
        """Record a verify-now result. `ok` is a real boolean here; the
        table stores it as 0/1. `ts` defaults to now() so tests can pass
        a fixed value."""
        self.conn.execute(
            "UPDATE pod_templates SET last_verified_at = ?, "
            "last_verified_ok = ?, last_verified_note = ? WHERE id = ?",
            (ts if ts is not None else _now(), 1 if ok else 0,
             (note or "")[:2000], template_id))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
