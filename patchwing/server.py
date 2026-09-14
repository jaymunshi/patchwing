"""
PatchWing control plane — a local web UI over the pipeline.

Stdlib only (http.server), consistent with the rest of the project. Serves a
dashboard and a small JSON API. The page shows every finding, lets you trigger
a run, and streams the event log live so you watch a vulnerability move through
the stages.

This is the CONTROL plane. It reads pipeline state and kicks off runs; it is not
where untrusted code executes. Execution belongs in the sandbox (containers on
the VM). Bind it to localhost — it exposes repo paths and model ids and has no
auth.
"""

from __future__ import annotations

import difflib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import arvo as arvo_mod
from . import budget as budget_mod
from . import bundle as bundle_mod
from . import models as models_mod
from .runner import Runner
from .store import STAGES, Store

HERE = os.path.dirname(os.path.abspath(__file__))
DASHBOARD = os.path.join(HERE, "web", "dashboard.html")
LANDING = os.path.join(HERE, "web", "landing.html")
LOGIN = os.path.join(HERE, "web", "login.html")


class RunState:
    """Tracks whether a run thread is active, so the UI can't double-fire it."""

    def __init__(self):
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.started_at: float | None = None
        self.last_finished: float | None = None

    @property
    def active(self) -> bool:
        return self.thread is not None and self.thread.is_alive()


PROVIDER_PRESETS = [
    {"id": "together", "label": "Together AI", "endpoint": "https://api.together.ai/v1", "key_env": "PATCHWING_PATCH_KEY", "model": "", "auth": "bearer"},
    {"id": "openai", "label": "OpenAI", "endpoint": "https://api.openai.com/v1", "key_env": "OPENAI_API_KEY", "model": "gpt-4o", "auth": "bearer"},
    {"id": "grok", "label": "Grok (xAI)", "endpoint": "https://api.x.ai/v1", "key_env": "XAI_API_KEY", "model": "grok-2", "auth": "bearer"},
    {"id": "claude", "label": "Claude (Anthropic native)", "endpoint": "https://api.anthropic.com/v1", "key_env": "ANTHROPIC_API_KEY", "model": "claude-sonnet-5", "auth": "x-api-key"},
    {"id": "ollama", "label": "Ollama / local", "endpoint": "http://localhost:11434/v1", "key_env": "", "model": "", "auth": "none"},
    {"id": "custom", "label": "Custom (OpenAI-compatible)", "endpoint": "", "key_env": "", "model": "", "auth": "bearer"},
]


def _template_to_dict(t) -> dict:
    """PodTemplate dataclass → JSON-serializable dict for API responses."""
    return {
        "id": t.id, "name": t.name, "description": t.description,
        "base_image": t.base_image, "image_tag": t.image_tag,
        "image_size_bytes": t.image_size_bytes,
        "image_digest": t.image_digest,
        "recipe_json": t.recipe_json,
        "recipe_turn_count": t.recipe_turn_count,
        "verification_cmd": t.verification_cmd,
        "verification_expect": t.verification_expect,
        "cve_class_hint": t.cve_class_hint,
        "builder_version": t.builder_version,
        "created_at": t.created_at,
        "last_verified_at": t.last_verified_at,
        "last_verified_ok": t.last_verified_ok,
        "last_verified_note": t.last_verified_note,
    }


class App:
    def __init__(self, db: str, config=None, workdir: str = ".patchwing",
                 config_path: str | None = None):
        self.db = db
        self.config = config
        self.workdir = workdir
        self.config_path = config_path
        self.run_state = RunState()
        self.ingest_state = RunState()
        try:
            self.apply_db_config()
        except Exception:
            pass
        # Seed the default admin/admin user on first start. Explicitly a shim
        # for pre-publish work — cleaned up before ship.
        try:
            self._seed_default_admin()
        except Exception:
            pass

    def _seed_default_admin(self) -> None:
        from . import auth
        s = self.store()
        try:
            if auth.count_users(s.conn) == 0:
                auth.add_user(s.conn, "admin", "admin")
        finally:
            s.close()

    def store(self) -> Store:
        # One connection per request keeps SQLite happy across threads.
        return Store(self.db)

    # -- run control ------------------------------------------------------

    def start_run(self, finding_id: str | None = None) -> dict:
        with self.run_state.lock:
            if self.run_state.active:
                return {"started": False, "reason": "a run is already active"}

            def worker():
                s = self.store()
                try:
                    if finding_id:
                        f = s.get(finding_id)
                        # Re-queue a blocked/failed finding so it advances again.
                        # A HUMAN requeue is the only reset that also zeroes the
                        # per-finding token counter — automated pipeline retries
                        # still accumulate, so the ceiling's unattended-runaway
                        # guard is preserved (see budget.py's docstring on why
                        # per-finding lifetime is otherwise deliberate). Rows
                        # are moved to kind=SPEND_PRIOR_KIND rather than deleted
                        # so the audit trail survives; only the LIVE `spend`
                        # rows count toward the ceiling.
                        if f and f.state in ("blocked", "failed"):
                            s.conn.execute(
                                "UPDATE artifacts SET kind = ? "
                                "WHERE finding_id = ? AND kind = ?",
                                (budget_mod.SPEND_PRIOR_KIND, finding_id,
                                 budget_mod.SPEND_KIND))
                            s.update(finding_id, state="pending", attempts=0,
                                     error="")
                    Runner(s, workdir=self.workdir, verbose=False,
                           config=self.config).run()
                finally:
                    s.close()
                    self.run_state.last_finished = time.time()

            t = threading.Thread(target=worker, daemon=True)
            self.run_state.thread = t
            self.run_state.started_at = time.time()
            t.start()
            return {"started": True}

    # -- read models ------------------------------------------------------

    def state(self) -> dict:
        s = self.store()
        try:
            findings = [self._finding_row(s, f) for f in s.list_findings(limit=200)]
            counts = s.counts()
        finally:
            s.close()
        return {
            "findings": findings,
            "counts": counts,
            "stages": STAGES,
            "run_active": self.run_state.active,
            "server_time": time.time(),
        }

    def _finding_row(self, s: Store, f) -> dict:
        return {
            "id": f.id, "title": f.title or f.source_ref or f.repo_url,
            "state": f.state, "stage": f.stage, "cwe": f.cwe,
            "source": f.source, "source_ref": f.source_ref,
            "attempts": f.attempts, "updated_at": f.updated_at,
            "stage_index": STAGES.index(f.stage) if f.stage in STAGES else -1,
        }

    def finding_detail(self, fid: str, since_event: int = 0) -> dict:
        s = self.store()
        try:
            f = s.get(fid)
            if f is None:
                return {"not_found": True}
            arts = s.artifacts(fid)
            events = []
            for e in s.events(fid):
                d = dict(e)
                # Parse meta once here so the browser never sees a JSON string.
                m = (d.get("meta") or "").strip()
                if m:
                    try:
                        d["meta"] = json.loads(m)
                    except (json.JSONDecodeError, TypeError):
                        d["meta"] = None
                else:
                    d["meta"] = None
                events.append(d)
            # Per-attempt token/USD counter + ceiling — surfaced so a climbing
            # number is visible in the UI before the ceiling trips (previously
            # invisible; only shown as "CEILING EXCEEDED" after the fact).
            spent = budget_mod.spent(s, fid)
            lifetime = budget_mod.total_lifetime(s, fid)
            ceiling = budget_mod.load_ceiling(s, self.config)
            budget_view = {
                # LIFETIME totals — this is what the dashboard shows now.
                # Includes spend + spend_prior + all descendant children.
                "lifetime_tokens": (lifetime.prompt_tokens
                                    + lifetime.completion_tokens),
                "lifetime_usd": round(lifetime.usd, 4),
                "lifetime_calls": lifetime.calls,
                "lifetime_priced": lifetime.priced,
                "lifetime_unpriced_calls": getattr(
                    lifetime, "unpriced_calls", 0),
                # ATTEMPT totals — retained for anyone diffing pre-lifetime
                # dashboards. Not shown by default.
                "tokens": spent.prompt_tokens + spent.completion_tokens,
                "usd": round(spent.usd, 4),
                "calls": spent.calls,
                "priced": spent.priced,
                "max_tokens": ceiling.max_tokens,
                "max_usd": ceiling.max_usd,
            }
            detail = {
                "id": f.id, "title": f.title, "state": f.state, "stage": f.stage,
                "cwe": f.cwe, "source": f.source, "source_ref": f.source_ref,
                "description": f.description, "error": f.error,
                "repo_url": f.repo_url, "base_commit": f.base_commit,
                "stages": STAGES,
                "events": [e for e in events if e["id"] > since_event],
                "artifacts": [self._artifact_summary(a) for a in arts],
                "diff": self._diff(s, f),
                "reference_patch": self._reference_patch(s, fid),
                "evidence": self._evidence(s, fid),
                "prompts": self._prompts(s, fid),
                "budget": budget_view,
            }
            return detail
        finally:
            s.close()

    def _artifact_summary(self, a) -> dict:
        return {"kind": a["kind"], "stage": a["stage"],
                "bytes": len(a["content"] or ""), "model": a["model"] or "",
                "created_at": a["created_at"]}

    def _diff(self, s: Store, f) -> str | None:
        patch = s.latest_artifact(f.id, "patch")
        if patch is None:
            return None
        try:
            meta = json.loads(patch["meta"] or "{}")
            rel = meta.get("file")
            spec_art = s.latest_artifact(f.id, "spec")
            spec = json.loads(spec_art["content"]) if spec_art else {}
            target = spec.get("_target_dir") or f.repo_url
            with open(os.path.join(target, rel), encoding="utf-8") as fh:
                original = fh.read()
        except (OSError, json.JSONDecodeError, TypeError):
            return None
        diff = difflib.unified_diff(
            original.splitlines(), patch["content"].splitlines(),
            f"a/{rel}", f"b/{rel}", lineterm="", n=3)
        return "\n".join(diff)

    def _evidence(self, s: Store, fid: str) -> str | None:
        ev = s.latest_artifact(fid, "evidence")
        return ev["content"] if ev else None

    # --- template library ---------------------------------------------
    # See docs/http-classifier-design.md and patchwing/templates.py for
    # the ownership boundary. Templates are global (no finding_id);
    # this section only READS + verify-now-writes, never mutates schema.

    def templates_list(self) -> dict:
        """All templates, newest first. Recipe body is omitted from the
        list view — the detail endpoint carries it. Keeps the library
        page's payload small."""
        s = self.store()
        try:
            rows = []
            for t in s.list_templates():
                d = _template_to_dict(t)
                d.pop("recipe_json", None)      # detail view carries this
                rows.append(d)
            return {"templates": rows}
        finally:
            s.close()

    def template_get(self, id_or_name: str) -> dict:
        """Full template detail including the parsed recipe. For the
        per-template audit page — a reader wants to see exactly which
        tool calls got run."""
        s = self.store()
        try:
            t = s.get_template(id_or_name)
            if t is None:
                return {"ok": False, "error": "template not found"}
            d = _template_to_dict(t)
            try:
                d["recipe"] = json.loads(t.recipe_json or "[]")
            except json.JSONDecodeError:
                d["recipe"] = []
            return {"ok": True, "template": d}
        finally:
            s.close()

    def template_verify(self, tid: str) -> dict:
        """Verify-now button — re-run the template's verification_cmd
        against a fresh pod from its image_tag, match against the stored
        regex, update last_verified_* atomically. Returns the reading so
        the UI can render feedback without a follow-up read."""
        from . import template_builder as tb_mod
        s = self.store()
        try:
            t = s.get_template(tid)
            if t is None:
                return {"ok": False, "error": "template not found"}
            try:
                result = tb_mod.verify_template(
                    store=s, sandbox_config=self.config.sandbox,
                    template=t)
            except Exception as e:
                return {"ok": False,
                        "error": f"verify raised: {type(e).__name__}: {e}"}
            # Re-read for the updated last_verified_at
            fresh = s.get_template(tid)
            return {"ok": True,
                    "verified_ok": result["ok"],
                    "error": result.get("error", ""),
                    "stdout_tail": result.get("stdout_tail", ""),
                    "last_verified_at": fresh.last_verified_at,
                    "last_verified_ok": fresh.last_verified_ok}
        finally:
            s.close()

    def draft_spec_get(self, fid: str) -> dict:
        """Return the operator-authored draft-spec for a finding, or {}.

        The draft-spec is a JSON artifact carrying the http sub-block a
        provisioner will merge with its own observations (URL etc) to
        produce the final spec. Structured this way — as a separate
        artifact kind — so the operator can author it before provision
        runs and revise it after."""
        s = self.store()
        try:
            f = s.get(fid)
            if f is None:
                return {"ok": False, "error": "finding not found"}
            art = s.latest_artifact(fid, "draft_spec")
            content = {}
            if art is not None and art["content"]:
                try:
                    content = json.loads(art["content"])
                except json.JSONDecodeError:
                    content = {}
            return {"ok": True, "draft": content,
                    "editable": self._draft_spec_editable(f)}
        finally:
            s.close()

    def draft_spec_save(self, fid: str, payload: dict) -> dict:
        """Validate + store the operator-authored draft-spec.

        Validation goes through spec.validate_http_block via a synthetic
        {reproducer_kind:'http', http:<payload>} — the operator only
        supplies the http sub-block, we wrap it so validation is the same
        code path Step 5 provision + reproduce use."""
        from . import spec as spec_mod
        s = self.store()
        try:
            f = s.get(fid)
            if f is None:
                return {"ok": False, "error": "finding not found"}
            if not self._draft_spec_editable(f):
                return {"ok": False,
                        "error": (f"finding at stage={f.stage!r} is not "
                                  "eligible for draft-spec authoring "
                                  "(need stage=localize + non-ARVO source)")}
            if not isinstance(payload, dict):
                return {"ok": False, "error": "payload must be a JSON object"}
            wrapped = {"reproducer_kind": "http", "http": payload}
            try:
                # Draft validator — url is provision's field, not the
                # operator's. See spec.py ownership boundary.
                spec_mod.validate_http_draft_block(wrapped)
                # Existence check for preferred_template — reject a
                # stale template name at SAVE, not later at provision.
                spec_mod.validate_preferred_template_exists(wrapped, s)
            except spec_mod.SpecError as e:
                return {"ok": False, "error": str(e)}
            s.add_artifact(fid, "draft_spec", "localize",
                           content=json.dumps(payload, indent=2, sort_keys=True),
                           meta={"source": "operator"}, base_commit="",
                           model="")
            return {"ok": True, "draft": payload}
        finally:
            s.close()

    def _draft_spec_editable(self, f) -> bool:
        """Whether the finding is eligible for draft-spec authoring.

        Step 4 rule: stage=localize AND source is NOT ARVO (i.e. the
        finding came from KEV/OSV and provision would need to build an
        image from scratch). ARVO findings ship their own spec; there is
        nothing for the operator to draft."""
        if f.stage != "localize":
            return False
        ref = (f.source_ref or "").upper()
        if ref.startswith("ARVO"):
            return False
        return True

    def target_spec_save(self, fid: str, payload: dict) -> dict:
        """Save an operator-authored target spec as a `spec` artifact.

        For non-ARVO advisory-source findings where no upstream fix
        commit exists, the operator can post {files, target?,
        reproducer?, http?, reproducer_kind?} here at stage=localize.
        The spec artifact is what localize's `_spec()` picks up on the
        next `run` — the file-declared branch fires and the finding
        advances to provision.

        Only allowed at stage=localize; refuses otherwise so we do not
        clobber a provision-authored spec later in the pipeline."""
        s = self.store()
        try:
            f = s.get(fid)
            if f is None:
                return {"ok": False, "error": "finding not found"}
            if f.stage != "localize":
                return {"ok": False,
                        "error": (f"finding at stage={f.stage!r} is not "
                                  "eligible for target-spec authoring "
                                  "(need stage=localize)")}
            if not isinstance(payload, dict):
                return {"ok": False, "error": "payload must be a JSON object"}
            files = payload.get("files")
            if not isinstance(files, list) or not files or not all(
                    isinstance(x, str) and x for x in files):
                return {"ok": False,
                        "error": "payload.files must be a non-empty list of strings"}
            # Synthesize the spec with sane defaults for the in-image
            # non-ARVO pathway.
            spec = {
                "files": files,
                "target": payload.get("target") or {"mode": "in-image", "root": "/"},
            }
            if "reproducer_kind" in payload:
                spec["reproducer_kind"] = payload["reproducer_kind"]
            if "http" in payload and isinstance(payload["http"], dict):
                spec["http"] = payload["http"]
            if "reproducer" in payload and isinstance(payload["reproducer"], dict):
                spec["reproducer"] = payload["reproducer"]
            if "suite" in payload and isinstance(payload["suite"], dict):
                spec["suite"] = payload["suite"]
            if "commands" in payload and isinstance(payload["commands"], dict):
                spec["commands"] = payload["commands"]
            # Rev-6 lockdown: strip bypass fields from operator API payloads.
            # These are ingest-only flags; the target-spec endpoint runs at
            # localize stage and MUST NOT be able to set them.
            if isinstance(spec.get("reproducer"), dict):
                spec["reproducer"].pop("origin", None)
            if isinstance(spec.get("target"), dict):
                spec["target"].pop("prebuilt", None)
            s.add_artifact(fid, "spec", "localize",
                           content=json.dumps(spec, indent=2, sort_keys=True),
                           meta={"source": "operator-target-spec-at-localize",
                                 "reason": "non-ARVO advisory-source: no upstream fix commit — operator attaches file list + target mode so localize can proceed"},
                           base_commit="", model="")
            return {"ok": True, "spec": spec}
        finally:
            s.close()

    def target_spec_get(self, fid: str) -> dict:
        """Return the latest spec artifact for a finding, or {}."""
        s = self.store()
        try:
            f = s.get(fid)
            if f is None:
                return {"ok": False, "error": "finding not found"}
            art = s.latest_artifact(fid, "spec")
            content = {}
            if art is not None and art["content"]:
                try:
                    content = json.loads(art["content"])
                except json.JSONDecodeError:
                    content = {}
            return {"ok": True, "spec": content,
                    "editable": (f.stage == "localize")}
        finally:
            s.close()



    def signoff(self, fid: str) -> dict:
        """Human accepts a review-stage finding. Flips state to done.

        Only valid for findings at stage=review (state=pending_signoff
        in the new semantics, or state=blocked in the legacy semantics —
        both accepted for migration compatibility). Any other stage would
        be a machine signing its own work off, which the review gate
        exists to prevent."""
        s = self.store()
        try:
            f = s.get(fid)
            if f is None:
                return {"ok": False, "error": "finding not found"}
            if f.stage != "review":
                return {"ok": False,
                        "error": (f"finding is at stage={f.stage!r}, not "
                                  "review — sign-off only applies to the "
                                  "human-gated review stage")}
            s.update(fid, state="done", error="")
            return {"ok": True, "state": "done", "stage": "review"}
        finally:
            s.close()

    def arvo_compare(self, fid: str) -> dict:
        """Generate the post-review ARVO commentary artifact for a finding.

        Runs ONE isolated model call whose ONLY job is prose comparison
        between our chain-proved patch and the ARVO developer patch. The
        ARVO patch is read from the offline archive and passed to this call
        only — it does not flow into the patch stage, verify stage, advisory
        seat, or four-state classifier. This method returns after the
        artifact is stored.
        """
        import datetime
        import json as _json
        s = self.store()
        try:
            f = s.get(fid)
            if f is None:
                return {"ok": False, "error": "finding not found"}
            # Post-review only. Refuse otherwise; the guardrail is that this
            # comparison must run AFTER the verdict is already final.
            if f.stage != "review":
                return {"ok": False,
                        "error": (f"finding is at stage={f.stage!r} — ARVO "
                                  "comparison only runs post-review")}

            # Idempotence: if we already generated one, return it.
            existing = s.latest_artifact(fid, "arvo_comparison")
            if existing is not None:
                em = _json.loads(existing["meta"] or "{}")
                return {"ok": True, "already_present": True,
                        "generated_at": em.get("generated_at", ""),
                        "arvo_id": em.get("arvo_id", "")}

            # Derive ARVO id and load the developer patch bytes. Refuse
            # explicitly if either fails — do NOT silently write an
            # "unavailable" artifact from the endpoint; that path is only
            # for bundle-assembly time when no arvo_comparison exists at all.
            try:
                arvo_id = arvo_mod.arvo_id_from_source_ref(f.source_ref or "")
            except arvo_mod.ArvoIdNotDerivable as e:
                return {"ok": False, "arvo_id": None,
                        "error": f"not an ARVO finding: {e}"}
            try:
                arvo_patch = arvo_mod.load_patch(arvo_id)
            except arvo_mod.ArvoPatchNotFound as e:
                return {"ok": False, "arvo_id": arvo_id,
                        "error": str(e),
                        "arvo_archive_incomplete": True}

            # Assemble inputs — all from the store, all already existing on
            # any finding that reached review.
            diff_art = s.latest_artifact(fid, "patch_diff")
            repro_art = s.latest_artifact(fid, "reproducer")
            if diff_art is None or repro_art is None:
                return {"ok": False,
                        "error": ("finding is missing patch_diff or "
                                  "reproducer artifact — cannot compare")}
            our_diff = diff_art["content"] or ""
            crash_trace = repro_art["content"] or ""
            invest_summary = arvo_mod.summarize_investigation(
                list(s.events(fid)))

            # One model call. Uses the patch seat's configured client (Kimi)
            # — it is NOT acting as fix-writer here, only as author of a
            # comparison. No budget-metered stage context; this counts against
            # the finding's cost the same way any other seat's call would.
            try:
                mcfg = self.config.model("patch")
            except Exception as e:
                return {"ok": False,
                        "error": f"no patch-seat model configured: {e}"}
            client = models_mod.Client(mcfg)
            try:
                # Use raw chat() — the comparison is prose-only, not JSON.
                # chat_json would insist on a JSON object even with
                # required=() and error out on clean markdown replies.
                raw_prose = client.chat(
                    [{"role": "system",
                      "content": arvo_mod.COMPARISON_SYSTEM},
                     {"role": "user",
                      "content": arvo_mod.build_comparison_user_message(
                          arvo_id=arvo_id,
                          our_diff=our_diff,
                          arvo_diff=arvo_patch.decode("utf-8",
                                                     errors="replace"),
                          crash_trace=crash_trace,
                          investigation_summary=invest_summary)}])
            except Exception as e:
                return {"ok": False,
                        "error": f"comparison model call failed: {e}"}
            # If the model still wrapped its prose in JSON (some hosted
            # models can't help themselves), try to unwrap; otherwise take
            # the raw text.
            prose = raw_prose or ""
            stripped = prose.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    parsed = _json.loads(stripped)
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, dict):
                    for key in ("prose", "comparison", "response", "content",
                                "text", "analysis", "body", "markdown"):
                        v = parsed.get(key)
                        if isinstance(v, str) and v.strip():
                            prose = v
                            break
                    else:
                        if len(parsed) == 1:
                            only_v = next(iter(parsed.values()))
                            if isinstance(only_v, str) and only_v.strip():
                                prose = only_v
            doc = arvo_mod.wrap_comparison_document(
                arvo_id=arvo_id, prose=prose)

            import hashlib
            arvo_sha = hashlib.sha256(arvo_patch).hexdigest()
            our_sha = hashlib.sha256(
                (our_diff or "").encode("utf-8")).hexdigest()
            generated_at = datetime.datetime.utcnow().strftime(
                "%Y-%m-%dT%H:%M:%SZ")

            # Persist the comparison as its own artifact kind. Bundle
            # assembler picks it up if present. Nothing in the judging path
            # ever reads this kind.
            s.add_artifact(
                fid, "arvo_comparison", "review",
                content=doc,
                meta={"arvo_id": arvo_id,
                      "arvo_patch_sha256": arvo_sha,
                      "our_patch_sha256": our_sha,
                      "generated_at": generated_at,
                      "model": mcfg.model,
                      "endpoint": mcfg.endpoint,
                      "origin": "OSS-Fuzz via ARVO",
                      "note": ("post-review commentary only; not a "
                               "verdict; reproducer is the sole judge")},
                model=mcfg.model)
            return {"ok": True, "arvo_id": arvo_id,
                    "generated_at": generated_at,
                    "arvo_patch_sha256": arvo_sha,
                    "our_patch_sha256": our_sha,
                    "bytes": len(doc)}
        finally:
            s.close()

    def iterate_once_more(self, fid: str) -> dict:
        """Prepare a finding for one more fix-writer iteration.

        Used after verify returned `different_bug` — the patch closed the
        original but exposed the next masked bug. This routine:

          1. Refuses if the previous iteration is not a valid iterate-on
             target (must be `different_bug`, `fix_did_not_resolve`, or
             manual override).
          2. Refuses if `pipeline.max_iterations` would be exceeded.
          3. Captures the LATEST reproducer artifact's four_state as the new
             pristine token (that's the bug being iterated on now).
          4. Rewrites the reproducer_lock with the new pristine token.
          5. Deletes previous patch/patch_diff/verdict artifacts so the patch
             stage runs fresh instead of returning the last patch.
          6. Resets the finding to patch/pending.

        Does NOT run the patch stage — caller kicks that separately via the
        existing /api/finding/<id>/run endpoint. Keeps the "user asked, then
        watched" flow the UI is built around.
        """
        s = self.store()
        try:
            f = s.get(fid)
            if f is None:
                return {"ok": False, "error": "finding not found"}

            # Cap check (via cfg — same source of truth as the CLI).
            cfg = self.config
            max_iter = getattr(getattr(cfg, "pipeline", None),
                               "max_iterations", 1)
            done = sum(1 for a in s.artifacts(fid, "patch"))
            if max_iter and done >= max_iter:
                return {"ok": False,
                        "error": (f"already ran {done} of "
                                  f"{max_iter} allowed iteration(s); raise "
                                  f"pipeline.max_iterations to continue")}

            # Only iterate from a state that has actual new information.
            allowed = ("verify_different_bug", "verify_fix_did_not_resolve")
            verdict = s.latest_artifact(fid, "verdict")
            outcome = ""
            try:
                if verdict is not None:
                    vmeta = json.loads(verdict["meta"] or "{}")
                    outcome = vmeta.get("outcome", "")
            except (json.JSONDecodeError, TypeError):
                pass
            if outcome and outcome not in allowed:
                return {"ok": False,
                        "error": (f"finding's last verdict is `{outcome}`; "
                                  f"iterate is only meaningful after "
                                  f"{', '.join(allowed)}")}

            repro = s.latest_artifact(fid, "reproducer")
            if repro is None:
                return {"ok": False,
                        "error": "no reproducer artifact — cannot re-anchor"}

            try:
                rmeta = json.loads(repro["meta"] or "{}")
            except (json.JSONDecodeError, TypeError):
                rmeta = {}
            reading = rmeta.get("four_state") or {}
            new_token = reading.get("dedup_token") or ""
            new_marker = reading.get("marker") or ""
            if not new_token or new_token == "(none)":
                return {"ok": False,
                        "error": ("latest reproducer artifact has no "
                                  "dedup_token — cannot use it as the new "
                                  "pristine anchor")}

            # Rewrite the lock's pristine token to the CURRENT bug so the four
            # state classifier stops comparing against the closed one.
            lock = s.latest_artifact(fid, "reproducer_lock")
            if lock is not None:
                try:
                    manifest = json.loads(lock["content"])
                except json.JSONDecodeError:
                    manifest = {}
                manifest["pristine_dedup_token"] = new_token
                manifest["pristine_marker"] = new_marker
                try:
                    lmeta = json.loads(lock["meta"] or "{}")
                except (json.JSONDecodeError, TypeError):
                    lmeta = {}
                lmeta["pristine_dedup_token"] = new_token
                s.conn.execute(
                    "UPDATE artifacts SET content = ?, meta = ? WHERE id = ?",
                    (json.dumps(manifest, indent=2, sort_keys=True),
                     json.dumps(lmeta), lock["id"]))

            # Drop stale artifacts so the fresh patch call has to actually run.
            s.conn.execute(
                "DELETE FROM artifacts WHERE finding_id = ? "
                "AND kind IN ('patch','patch_diff','verdict','prompt')",
                (fid,))
            s.update(fid, state="pending", stage="patch",
                     attempts=0, error="")
            s.conn.commit()
            s.log(fid, "patch", "queued",
                  f"iteration {done+1} of {max_iter or 'unbounded'} — new "
                  f"pristine token: {new_token}")
            return {"ok": True, "iteration": done + 1,
                    "new_pristine_token": new_token,
                    "max_iterations": max_iter}
        finally:
            s.close()

    def _prompts(self, s: Store, fid: str) -> list[dict]:
        """Every model prompt sent for this finding, oldest first.

        Read by the dashboard so a user can see EXACTLY what went to which
        model. Without this the only visible model artefact is the diff, and
        there is no way to tell whether a bad answer was a bad model or a bad
        prompt.
        """
        out = []
        for a in s.artifacts(fid, "prompt"):
            try:
                meta = json.loads(a["meta"] or "{}")
            except (json.JSONDecodeError, TypeError):
                meta = {}
            out.append({
                "id": a["id"],
                "stage": a["stage"],
                "seat": meta.get("seat", ""),
                "model": meta.get("model", "") or a["model"] or "",
                "endpoint": meta.get("endpoint", ""),
                "temperature": meta.get("temperature"),
                "max_tokens": meta.get("max_tokens"),
                "system_message": meta.get("system_message", ""),
                "user_message": a["content"],
                "user_message_bytes": meta.get("user_message_bytes",
                                               len(a["content"] or "")),
                "user_message_lines": meta.get("user_message_lines"),
                "primary_file": meta.get("primary_file", ""),
                "context_files": meta.get("context_files") or [],
                "localization_source": meta.get("localization_source", ""),
                "view": meta.get("view", ""),
                "window_lines": meta.get("window_lines"),
                "created_at": a["created_at"],
            })
        return out

    def _reference_patch(self, s: Store, fid: str) -> dict | None:
        ref = s.latest_artifact(fid, "reference_patch")
        if ref is None:
            return None
        meta = json.loads(ref["meta"] or "{}")
        return {"patch": ref["content"], "commit_url": meta.get("commit_url", ""),
                "message": meta.get("message", "")}

    # -- intake feed ------------------------------------------------------

    def advisories(self, filters: dict) -> dict:
        from . import feeds
        s = self.store()
        try:
            def flag(k):
                v = filters.get(k)
                return None if v is None else (v in ("1", "true", "yes"))
            rows = feeds.query(
                s,
                exploited=flag("exploited"),
                actionable=flag("actionable"),
                ransomware=flag("ransomware"),
                feed_class=filters.get("feed_class") or None,
                category=filters.get("category") or None,
                min_epss=float(filters["min_epss"]) if filters.get("min_epss") else None,
                search=filters.get("search") or None,
                order=filters.get("order", "epss"),
                limit=int(filters.get("limit", 200)),
                offset=int(filters.get("offset", 0)),
            )
            return {"advisories": rows, "facets": feeds.facets(s),
                    "ingest_active": self.ingest_state.active}
        finally:
            s.close()

    def promote(self, cve: str) -> dict:
        s = self.store()
        try:
            a = s.conn.execute("SELECT * FROM advisories WHERE cve=?", (cve,)).fetchone()
            if a is None:
                return {"error": "unknown cve"}
            if a["promoted_finding"]:
                return {"error": "already promoted", "finding": a["promoted_finding"]}
            from .feeds import is_supply_chain
            if a["category"] == "supply-chain" or is_supply_chain(
                    a["title"], a["description"]):
                return {"error": "supply-chain / malicious-publish advisory — "
                        "no code vulnerability to patch; the fix was a clean "
                        "republish, not a diff PatchWing can generate"}
            if a["feed_class"] != "production":
                return {"error": (
                    f"not promotable — feed_class={a['feed_class']!r}; "
                    "only 'production' advisories (no upstream fix + real "
                    "upstream project repo) can be promoted"),
                    "feed_class": a["feed_class"]}
            f = s.add_finding(
                source="advisory", source_ref=cve,
                repo_url=a["repo_url"] or f"(no repo) {a['product']}",
                cwe="", title=a["title"] or cve,
                description=(a["description"] or "") +
                (f"\n\nOSS: {a['ecosystem']} / {a['package']}, fixed in "
                 f"{a['fixed_version']}." if a["actionable"] else ""),
            )
            s.update(f.id, base_commit="")
            s.conn.execute("UPDATE advisories SET promoted_finding=? WHERE cve=?",
                           (f.id, cve))
            s.conn.commit()
            return {"finding": f.id, "actionable": bool(a["actionable"])}
        finally:
            s.close()

    def _db_config_table(self, s) -> None:
        s.conn.execute(
            "CREATE TABLE IF NOT EXISTS model_config("
            "role TEXT PRIMARY KEY, endpoint TEXT, model TEXT, api_key TEXT, "
            "api_key_env TEXT, temperature REAL, max_tokens INTEGER, "
            "timeout_s INTEGER, updated_at REAL)")
        try:
            s.conn.execute("ALTER TABLE model_config ADD COLUMN extra TEXT")
        except Exception:
            pass
        # Pipeline + fix-writer defaults. UI-editable overrides that stages.py
        # and the CLI read at run-time. Simple key/value so we do not need a
        # migration every time a knob is added. Values stored as TEXT — the
        # reader coerces.
        s.conn.execute(
            "CREATE TABLE IF NOT EXISTS pipeline_settings("
            " key TEXT PRIMARY KEY, value TEXT, updated_at REAL)")
        # System-prompt overrides — the exact text sent as the model's system
        # message per seat. Empty means "use built-in default from stages.py".
        # Reader (stages.py) checks this table before falling back to the
        # hardcoded constant. That's how the UI edit takes effect on the next
        # run without redeploying code.
        s.conn.execute(
            "CREATE TABLE IF NOT EXISTS prompt_overrides("
            " name TEXT PRIMARY KEY, body TEXT, updated_at REAL)")
        s.conn.commit()

    # Whitelisted keys the UI is allowed to touch. Anything else is refused —
    # so the settings table cannot become a dumping ground and the UI cannot
    # smuggle unknown fields into the pipeline.
    _PIPELINE_KEYS = {
        "max_iterations":       ("int",   1),   # 0 = disable auto-iterate
        "iteration_mode":       ("str",   "bounded"),   # "bounded" | "after_each"
        "context_max_bytes":    ("int",   0),   # 0 = unlimited
        "include_context":      ("bool",  True),
        "fix_writer_view":      ("str",   "window"),    # "window" | "whole_file"
    }

    def _pipeline_settings(self) -> dict:
        s = self.store()
        try:
            self._db_config_table(s)
            rows = {r["key"]: r["value"]
                    for r in s.conn.execute(
                        "SELECT key, value FROM pipeline_settings")}
        finally:
            s.close()
        out = {}
        for k, (typ, default) in self._PIPELINE_KEYS.items():
            raw = rows.get(k)
            if raw is None:
                out[k] = default
                continue
            if typ == "int":
                try: out[k] = int(raw)
                except (TypeError, ValueError): out[k] = default
            elif typ == "bool":
                out[k] = str(raw).lower() in ("1", "true", "yes", "on")
            else:
                out[k] = raw
        return out

    # System prompts the UI can edit. Names match the constants in stages.py
    # (PATCH_SYSTEM, REVIEW_SYSTEM) and symptom.py (RANK_SYSTEM). Reader-side
    # fallback lives in stages/symptom themselves.
    _PROMPTS = [
        ("PATCH_SYSTEM",
         "sent to the patch seat before the fix prompt"),
        ("REVIEW_SYSTEM",
         "sent to the verify seat for advisory review AFTER the container ruled"),
        ("RANK_SYSTEM",
         "sent to the detect seat during symptom-based localization"),
    ]

    def _prompts_read(self) -> dict:
        s = self.store()
        try:
            self._db_config_table(s)
            rows = {r["name"]: r["body"]
                    for r in s.conn.execute("SELECT name, body FROM prompt_overrides")}
        finally:
            s.close()
        # Pull the built-ins live from the code so the UI never drifts.
        from . import stages as stages_mod
        from . import symptom as symptom_mod
        builtins = {"PATCH_SYSTEM": stages_mod.PATCH_SYSTEM,
                    "REVIEW_SYSTEM": stages_mod.REVIEW_SYSTEM,
                    "RANK_SYSTEM": symptom_mod.RANK_SYSTEM}
        out = []
        for name, desc in self._PROMPTS:
            b = builtins.get(name, "")
            out.append({
                "name": name, "description": desc,
                "builtin": b, "builtin_bytes": len(b),
                "override": rows.get(name, ""),
            })
        return {"prompts": out}

    def _prompts_save(self, payload: dict) -> dict:
        import time as _tm
        overrides = (payload or {}).get("overrides") or {}
        s = self.store()
        try:
            self._db_config_table(s)
            for name, body in overrides.items():
                if name not in {n for n, _ in self._PROMPTS}:
                    continue
                body = (body or "").strip()
                if body:
                    s.conn.execute(
                        "INSERT OR REPLACE INTO prompt_overrides "
                        "(name, body, updated_at) VALUES (?, ?, ?)",
                        (name, body, _tm.time()))
                else:
                    # Empty means "clear the override, use built-in".
                    s.conn.execute(
                        "DELETE FROM prompt_overrides WHERE name = ?", (name,))
            s.conn.commit()
        finally:
            s.close()
        return {"ok": True}

    def _save_pipeline_settings(self, payload: dict) -> dict:
        import time as _tm
        s = self.store()
        try:
            self._db_config_table(s)
            for k, v in (payload or {}).items():
                if k not in self._PIPELINE_KEYS:
                    continue
                s.conn.execute(
                    "INSERT OR REPLACE INTO pipeline_settings "
                    "(key, value, updated_at) VALUES (?, ?, ?)",
                    (k, str(v), _tm.time()))
            s.conn.commit()
        finally:
            s.close()
        return {"ok": True, "settings": self._pipeline_settings()}

    def _db_rows(self) -> dict:
        s = self.store()
        try:
            self._db_config_table(s)
            return {r["role"]: dict(r)
                    for r in s.conn.execute("SELECT * FROM model_config")}
        finally:
            s.close()

    def apply_db_config(self) -> None:
        """Overlay DB-stored provider config onto the live config. DB wins."""
        if self.config is None:
            return
        from .config import ModelConfig
        # Pass 2 added "provision" to config.ROLES but this allowlist
        # was not updated in the same pass — a provision row in
        # model_config was silently skipped, and provision blocked with
        # ConfigError("no model configured for role 'provision'"). Read
        # the allowlist from config.ROLES so future role additions are
        # a one-line change.
        from . import config as _cfg
        for role, r in self._db_rows().items():
            if role not in _cfg.ROLES:
                continue
            if not r.get("endpoint") or not r.get("model"):
                continue
            key = r.get("api_key") or (
                os.environ.get(r["api_key_env"], "") if r.get("api_key_env") else "")
            self.config.models[role] = ModelConfig(
                role=role, endpoint=r["endpoint"].rstrip("/"), model=r["model"],
                api_key=key, api_key_env=r.get("api_key_env") or "",
                temperature=float(r.get("temperature") or 0.2),
                max_tokens=int(r.get("max_tokens") or 4096),
                timeout_s=int(r.get("timeout_s") or 300),
                extra=json.loads(r.get("extra") or "{}"))

    def get_config(self) -> dict:
        from . import config as cfgmod
        c = self.config
        dbr = self._db_rows()

        def role(rname):
            m = c.models.get(rname) if c else None
            r = dbr.get(rname, {})
            if not m and not r:
                return None
            endpoint = r.get("endpoint") or (m.endpoint if m else "")
            model = r.get("model") or (m.model if m else "")
            env = r.get("api_key_env") if r.get("api_key_env") is not None else (m.api_key_env if m else "")
            stored = r.get("api_key") or ""
            env_present = bool(env) and bool(os.environ.get(env or ""))
            hint = ("stored ****" + stored[-4:]) if len(stored) > 4 else ("stored" if stored else ("env:" + env if env_present else ""))
            return {"endpoint": endpoint, "model": model,
                    "family": cfgmod.family_of(model),
                    "api_key_env": env or "",
                    "api_key_set": bool(stored) or env_present,
                    "api_key_stored": bool(stored), "api_key_hint": hint,
                    "temperature": r.get("temperature") if r.get("temperature") is not None else (m.temperature if m else 0.2),
                    "max_tokens": r.get("max_tokens") or (m.max_tokens if m else 4096),
                    "timeout_s": r.get("timeout_s") or (m.timeout_s if m else 300),
                    "extra": json.loads(r.get("extra") or "{}")}
        from . import budget as budgetmod
        s = self.store()
        try:
            ceil = budgetmod.load_ceiling(s, c)
        finally:
            s.close()
        return {"roles": list(cfgmod.ROLES),
                "models": {rn: role(rn) for rn in cfgmod.ROLES},
                "sandbox": {"backend": c.sandbox.backend, "network": c.sandbox.network} if c else {},
                "pipeline": {"db": c.pipeline.db, "max_attempts": c.pipeline.max_attempts} if c else {},
                # Per-finding cost ceiling, summed across every seat. 0 disables a
                # limit; both at 0 means an unattended run has no upper bound.
                "cost_ceiling": {"max_tokens": ceil.max_tokens,
                                 "max_usd": ceil.max_usd,
                                 "default_tokens": budgetmod.DEFAULT_MAX_TOKENS,
                                 "default_usd": budgetmod.DEFAULT_MAX_USD},
                "warnings": c.warnings if c else [], "config_path": self.config_path,
                "presets": PROVIDER_PRESETS}

    def update_config(self, payload: dict) -> dict:
        import time
        from . import config as cfgmod
        s = self.store()
        try:
            self._db_config_table(s)
            existing = {r["role"]: dict(r)
                        for r in s.conn.execute("SELECT * FROM model_config")}
            for rname, patch in (payload.get("models") or {}).items():
                if rname not in cfgmod.ROLES:
                    continue
                ex = existing.get(rname, {})
                endpoint = (patch.get("endpoint") or ex.get("endpoint") or "").rstrip("/")
                model = patch.get("model") or ex.get("model") or ""
                if not endpoint or not model:
                    continue
                env = patch.get("api_key_env", ex.get("api_key_env") or "")
                newkey = patch.get("api_key")
                key = newkey if newkey else (ex.get("api_key") or "")
                newextra = patch.get("extra")
                extra_json = json.dumps(newextra) if newextra is not None else (ex.get("extra") or "{}")
                s.conn.execute(
                    "INSERT INTO model_config(role,endpoint,model,api_key,api_key_env,"
                    "temperature,max_tokens,timeout_s,extra,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(role) DO UPDATE SET endpoint=excluded.endpoint,"
                    "model=excluded.model,api_key=excluded.api_key,"
                    "api_key_env=excluded.api_key_env,temperature=excluded.temperature,"
                    "max_tokens=excluded.max_tokens,timeout_s=excluded.timeout_s,"
                    "extra=excluded.extra,updated_at=excluded.updated_at",
                    (rname, endpoint, model, key, env,
                     float(patch.get("temperature", ex.get("temperature") or 0.2)),
                     int(patch.get("max_tokens", ex.get("max_tokens") or 4096)),
                     int(patch.get("timeout_s", ex.get("timeout_s") or 300)),
                     extra_json, time.time()))
            cc = payload.get("cost_ceiling")
            if isinstance(cc, dict):
                from . import budget as budgetmod
                cur = budgetmod.load_ceiling(s, self.config)
                budgetmod.save_ceiling(
                    s,
                    max_tokens=cc.get("max_tokens", cur.max_tokens),
                    max_usd=cc.get("max_usd", cur.max_usd))
            s.conn.commit()
        finally:
            s.close()
        self.apply_db_config()
        if self.config_path and self.config:
            try:
                cfgmod.save(self.config, self.config_path)
            except Exception:
                pass
        return self.get_config()

    def preflight_config(self, payload: dict) -> dict:
        from .config import ModelConfig
        from .models import Client
        role = payload.get("role", "patch")
        endpoint = (payload.get("endpoint") or "").rstrip("/")
        model = payload.get("model") or ""
        if endpoint and model:
            env = payload.get("api_key_env", "")
            key = payload.get("api_key") or (os.environ.get(env, "") if env else "")
            if not key:
                m = self.config.models.get(role) if self.config else None
                if m and m.endpoint == endpoint and m.model == model:
                    key = m.api_key
            cfg = ModelConfig(role=role, endpoint=endpoint, model=model,
                              api_key=key, api_key_env=env,
                              max_tokens=int(payload.get("max_tokens", 4096)),
                              timeout_s=int(payload.get("timeout_s", 120)))
        else:
            m = self.config.models.get(role) if self.config else None
            if not m:
                return {"error": f"role '{role}' is not configured"}
            cfg = m
        try:
            return Client(cfg).preflight()
        except Exception as e:
            return {"error": str(e)}

    def start_ingest(self, osv_limit: int = 150) -> dict:
        with self.ingest_state.lock:
            if self.ingest_state.active:
                return {"started": False, "reason": "ingest already running"}
            from . import feeds

            def worker():
                s = self.store()
                try:
                    feeds.ingest(s, osv_limit=osv_limit, log=lambda m: None)
                finally:
                    s.close()
                    self.ingest_state.last_finished = time.time()

            t = threading.Thread(target=worker, daemon=True)
            self.ingest_state.thread = t
            self.ingest_state.started_at = time.time()
            t.start()
            return {"started": True}


class Handler(BaseHTTPRequestHandler):
    app: App = None  # set on the server instance

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def _read_json(self) -> dict:
        try:
            ln = int(self.headers.get("Content-Length", 0) or 0)
            return json.loads(self.rfile.read(ln).decode("utf-8")) if ln else {}
        except Exception:
            return {}

    def _serve_file(self, fpath, name):
        try:
            with open(fpath, "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
        except OSError:
            self._send(500, (name + " missing").encode(), "text/plain")

    def _handle_bundle_download(self, fid: str) -> None:
        """Stream the portable evidence bundle for a finding as .tar.gz."""
        s = self.app.store()
        try:
            try:
                result = bundle_mod.assemble(s, fid)
            except bundle_mod.BundleAssemblyError as e:
                return self._json({"ok": False, "error": str(e),
                                   "missing": e.missing}, 409)
            body = result.bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{result.filename}"')
            self.end_headers()
            self.wfile.write(body)
        finally:
            s.close()

    def _handle_login(self) -> None:
        from . import auth
        body = self._read_json() or {}
        email = str(body.get("email", ""))
        password = str(body.get("password", ""))
        if not email or not password:
            return self._json({"ok": False,
                               "error": "username and password are required"}, 400)
        s = self.app.store()
        try:
            uid = auth.authenticate(s.conn, email, password)
        finally:
            s.close()
        if uid is None:
            return self._json({"ok": False,
                               "error": "invalid username or password"}, 401)
        s = self.app.store()
        try:
            token = auth.start_session(s.conn, uid)
        finally:
            s.close()
        body_bytes = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Set-Cookie", auth.session_cookie(token))
        self.end_headers()
        self.wfile.write(body_bytes)

    def _handle_logout(self) -> None:
        from . import auth
        cookies = auth.parse_cookie(self.headers.get("Cookie", ""))
        token = cookies.get(auth.COOKIE_NAME, "")
        s = self.app.store()
        try:
            auth.end_session(s.conn, token)
        finally:
            s.close()
        body_bytes = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Set-Cookie", auth.logout_cookie())
        self.end_headers()
        self.wfile.write(body_bytes)

    # --- auth middleware -------------------------------------------------
    # Every non-public route requires a valid pw_session cookie. Anonymous
    # requests get 302 -> /login for pages and 401 for API endpoints.
    _PUBLIC_PATHS = frozenset({"/login", "/api/login", "/favicon.ico"})

    def _current_user(self) -> dict | None:
        from . import auth
        cookies = auth.parse_cookie(self.headers.get("Cookie", ""))
        token = cookies.get(auth.COOKIE_NAME, "")
        if not token:
            return None
        s = self.app.store()
        try:
            return auth.resolve_session(s.conn, token)
        finally:
            s.close()

    def _require_auth(self, path: str) -> bool:
        """True if the request is allowed to proceed; False if a 401/302 was sent."""
        if path in self._PUBLIC_PATHS:
            return True
        if self._current_user() is not None:
            return True
        # Unauthenticated. API → 401, pages → 302 login with a next-hop.
        if path.startswith("/api/"):
            self._json({"error": "authentication required"}, 401)
        else:
            import urllib.parse as _up
            nxt = "/login?next=" + _up.quote(path, safe="/")
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("Content-Length", "0")
            self.end_headers()
        return False

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        query = {}
        if "?" in self.path:
            for kv in self.path.split("?", 1)[1].split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    query[k] = v

        # Login page is public.
        if path == "/login":
            return self._serve_file(LOGIN, "login.html")

        if not self._require_auth(path):
            return

        if path == "/":
            self._serve_file(LANDING, "landing.html")
        elif path in ("/app", "/pipeline", "/console"):
            self._serve_file(DASHBOARD, "dashboard.html")
        elif path == "/api/state":
            self._json(self.app.state())
        elif path == "/api/config":
            self._json(self.app.get_config())
        elif path == "/api/whoami":
            u = self._current_user()
            self._json({"user": u} if u else {"user": None})
        elif path == "/api/pipeline_settings":
            self._json({"settings": self.app._pipeline_settings(),
                        "schema": {k: {"type": t, "default": d}
                                   for k, (t, d) in self.app._PIPELINE_KEYS.items()}})
        elif path == "/api/prompts":
            self._json(self.app._prompts_read())
        elif path == "/providers":
            pp = os.path.join(HERE, "web", "providers.html")
            try:
                with open(pp, "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(500, b"providers.html missing", "text/plain")
        elif path == "/templates":
            # Library page — same HTML serves the index AND the per-
            # template detail view (query fragment #<id> or ?id=<id>).
            tp = os.path.join(HERE, "web", "templates.html")
            try:
                with open(tp, "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(500, b"templates.html missing", "text/plain")
        elif path == "/api/templates":
            self._json(self.app.templates_list())
        elif path.startswith("/api/templates/"):
            tid = path.rsplit("/", 1)[-1]
            self._json(self.app.template_get(tid))
        elif path == "/api/advisories":
            self._json(self.app.advisories(query))
        elif (path.startswith("/api/finding/") and path.endswith("/bundle")):
            # Portable evidence bundle. Streams a .tar.gz built entirely from
            # store artifacts — no pod touch, no model call. See bundle.py.
            fid = path.split("/")[3]
            self._handle_bundle_download(fid)
        elif (path.startswith("/api/finding/")
              and path.endswith("/draft-spec")):
            # Operator-authored HTTP evidence rules + endpoint metadata.
            # Only usable at stage=localize on non-ARVO findings; the
            # editor in the UI hides itself outside that window.
            fid = path.split("/")[3]
            self._json(self.app.draft_spec_get(fid))
        elif (path.startswith("/api/finding/")
              and path.endswith("/target-spec")):
            # Operator-authored target spec (files + target + optional
            # reproducer/http). Non-ARVO MVP: unblocks findings whose
            # upstream fix commit cannot be resolved.
            fid = path.split("/")[3]
            self._json(self.app.target_spec_get(fid))
        elif path.startswith("/api/finding/"):
            fid = path.rsplit("/", 1)[-1]
            since = int(query.get("since", 0))
            self._json(self.app.finding_detail(fid, since))
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]

        # /api/login is public — this IS how a user gets a session.
        if path == "/api/login":
            return self._handle_login()
        if not self._require_auth(path):
            return
        if path == "/api/logout":
            return self._handle_logout()

        if path == "/api/run":
            self._json(self.app.start_run())
        elif path == "/api/config":
            self._json(self.app.update_config(self._read_json()))
        elif path == "/api/preflight":
            self._json(self.app.preflight_config(self._read_json()))
        elif path == "/api/pipeline_settings":
            self._json(self.app._save_pipeline_settings(self._read_json() or {}))
        elif path == "/api/prompts":
            self._json(self.app._prompts_save(self._read_json() or {}))
        elif path == "/api/feeds/pull":
            self._json(self.app.start_ingest())
        elif (path.startswith("/api/templates/")
              and path.endswith("/verify")):
            tid = path.split("/")[3]
            self._json(self.app.template_verify(tid))
        elif path.startswith("/api/finding/") and path.endswith("/run"):
            fid = path.split("/")[3]
            self._json(self.app.start_run(fid))
        elif path.startswith("/api/finding/") and path.endswith("/iterate"):
            fid = path.split("/")[3]
            self._json(self.app.iterate_once_more(fid))
        elif (path.startswith("/api/finding/")
              and path.endswith("/draft-spec")):
            fid = path.split("/")[3]
            self._json(self.app.draft_spec_save(fid, self._read_json() or {}))
        elif (path.startswith("/api/finding/")
              and path.endswith("/target-spec")):
            fid = path.split("/")[3]
            self._json(self.app.target_spec_save(fid, self._read_json() or {}))
        elif (path.startswith("/api/finding/")
              and path.endswith("/signoff")):
            # Human sign-off. Only valid on review-stage findings; flips
            # state to done. See App.signoff for the guard.
            fid = path.split("/")[3]
            self._json(self.app.signoff(fid))
        elif (path.startswith("/api/finding/")
              and path.endswith("/arvo-compare")):
            # Post-review ARVO commentary. Runs only when the finding is at
            # stage=review with a final verdict. Reads the offline ARVO
            # developer patch, calls one isolated model with it + our diff +
            # crash trace + investigation summary, stores the prose output
            # as an artifact. The ARVO patch NEVER flows into the patch
            # stage, verify stage, advisory seat, or four-state classifier.
            fid = path.split("/")[3]
            self._json(self.app.arvo_compare(fid))
        elif path.startswith("/api/advisory/") and path.endswith("/promote"):
            cve = path.split("/")[3]
            self._json(self.app.promote(cve))
        else:
            self._json({"error": "not found"}, 404)


def serve(db: str, host: str = "127.0.0.1", port: int = 8700,
          config=None, workdir: str = ".patchwing", config_path: str | None = None) -> None:
    app = App(db, config=config, workdir=workdir, config_path=config_path)
    Handler.app = app
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"patchwing control plane on http://{host}:{port}  (db={db})",
          flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding to a non-local address. This UI has no auth and "
              "exposes repo paths and model ids.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
        httpd.shutdown()
