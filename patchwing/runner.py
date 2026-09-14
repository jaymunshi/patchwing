"""
The runner: advance findings through stages until nothing is ready.

Deliberately not a workflow engine. Findings are rows, stages are functions,
and progress is a loop. When this stops being enough — durable retries across
machines — the stage contract ports to Temporal without callers changing.
"""

from __future__ import annotations

import sqlite3
import time
import traceback
import urllib.error
from dataclasses import dataclass

from . import models as models_mod
from . import outcomes as outcomes_mod
from . import sandbox as sandbox_mod
from . import stages
from .stages import BLOCKED, FAIL, OK, REJECT, RETRY, StageResult
from .store import (STATE_BLOCKED, STATE_DONE, STATE_FAILED, STATE_PENDING,
                    STATE_REJECTED, Finding, Store)

# Classes where a SECOND attempt could plausibly succeed. Deliberately short, and
# deliberately NOT a taxonomy of failure modes nobody has observed yet.
#
# SandboxError is here whole, not split into transient and permanent. The exception
# type is the wrong discriminator — which is precisely why both kinds land in it —
# so it gets exactly one retry and then the truth. The real distribution comes from
# the run, not from a guess made before the run.
_RETRY_ONCE = (sandbox_mod.SandboxError, sqlite3.OperationalError,
               models_mod.ModelError, urllib.error.URLError)

# Checked BEFORE _RETRY_ONCE: subclasses of the above that are never transient. A
# 401 does not become a 200 because you asked twice.
_NEVER_RETRY = (models_mod.AuthError,)

# Everything else terminates on the first raise. Most of what lands in the catch is
# deterministic at the same ceiling — disk-full, OOM, DB lock, KeyError,
# AttributeError, TypeError — and a retry that cannot succeed is not a retry, it is
# three copies of one failure. Each one here costs a rebuild of a 6.57 GB tree.

# Machine-readable first line of `findings.error`, so attempt 2 can tell whether it
# failed the same way as attempt 1. Carried in an existing column on purpose: the
# run_id/attempt migration is deferred to a watched session and must not happen here.
_SIG_PREFIX = "patchwing-failure-signature: "


@dataclass
class Ctx:
    store: Store
    workdir: str
    config: object | None = None


class Runner:
    def __init__(self, store: Store, workdir: str = ".patchwing",
                 max_attempts: int = 3, verbose: bool = True,
                 config: object | None = None):
        self.store = store
        self.ctx = Ctx(store=store, workdir=workdir, config=config)
        self.max_attempts = max_attempts
        self.verbose = verbose

    def _say(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def run_once(self) -> bool:
        """Advance a single finding by one stage. False when nothing is ready."""
        f = self.store.claim_next(max_attempts=self.max_attempts)
        if f is None:
            return False
        self._advance(f)
        return True

    def run(self, limit: int | None = None) -> int:
        n = 0
        while self.run_once():
            n += 1
            if limit and n >= limit:
                break
        return n

    def _advance(self, f: Finding) -> None:
        fn = stages.get(f.stage)
        if fn is None:
            self.store.update(f.id, state=STATE_FAILED,
                              error=f"no implementation for stage '{f.stage}'")
            self.store.log(f.id, f.stage, "fail", "unknown stage")
            return

        started = time.time()
        try:
            result = fn(f, self.ctx)
        except Exception as e:
            # C.2: the previous `except UnknownOutcome: raise` branch is deleted.
            # After outcomes.validate() safe-degrade (C.1), UnknownOutcome is no
            # longer raised in-tree — it's returned as HARNESS_UNKNOWN_OUTCOME and
            # routed through the normal FAIL path. Any exception here is a genuine
            # harness fault, and _record_harness_failure handles it exactly as
            # designed. Doctrine: a dead worker strands the finding; loud verdict
            # (FAILED state + error) is what "fail loud" actually means.
            self._record_harness_failure(f, e, time.time() - started)
            return

        elapsed = time.time() - started
        for art in result.artifacts:
            self.store.add_artifact(f.id, stage=f.stage, **art)

        self.store.log(f.id, f.stage, result.status, result.message, elapsed)

        if result.status == OK:
            nxt = f.next_stage()
            if nxt is None:
                self.store.update(f.id, state=STATE_DONE, error="")
                self._teardown_pod(f)
                self._say(f"  {f.id} complete")
            else:
                self.store.update(f.id, stage=nxt, state=STATE_PENDING,
                                  attempts=0, error="")
                self._say(f"  {f.id} {f.stage} → {nxt}")

        elif result.status == RETRY:
            attempts = f.attempts + 1
            state = STATE_PENDING if attempts < self.max_attempts else STATE_FAILED
            self.store.update(f.id, state=state, attempts=attempts,
                              error=result.message)
            if state == STATE_FAILED:
                self._teardown_pod(f)
            self._say(f"  {f.id} {f.stage}: retry {attempts}/{self.max_attempts}")

        elif result.status == BLOCKED:
            # BLOCKED is NOT terminal — a blocked finding can be unblocked and
            # continue. Pod stays alive so the next stage can attach.
            self.store.update(f.id, state=STATE_BLOCKED, error=result.message)
            self._say(f"  {f.id} {f.stage}: blocked — {result.message}")

        elif result.status == REJECT:
            self.store.update(f.id, state=STATE_REJECTED, error=result.message)
            self._teardown_pod(f)
            self._say(f"  {f.id} rejected — {result.message}")

        else:  # FAIL
            self.store.update(f.id, state=STATE_FAILED, error=result.message)
            self._teardown_pod(f)
            self._say(f"  {f.id} {f.stage}: failed — {result.message}")

    def _teardown_pod(self, f: Finding) -> None:
        """Stop and remove the finding's pod on a terminal transition.

        Pod-per-finding (change 2) lifecycle end. Runs on DONE / REJECTED /
        FAILED / final-RETRY-that-becomes-FAILED. Does NOT run on BLOCKED —
        a human might unblock and resume. Missing container is fine
        (already gone); this is defence, not the enforcement.
        """
        cid = (getattr(f, "container_id", "") or "").strip()
        if not cid:
            return
        cfg = getattr(self.ctx, "config", None)
        backend = (getattr(getattr(cfg, "sandbox", None), "backend", "")
                   or "podman")
        import subprocess
        try:
            subprocess.run([backend, "rm", "-f", cid],
                           capture_output=True, text=True, timeout=30)
        except Exception:
            pass
        try:
            self.store.update(f.id, container_id="")
        except Exception:
            pass
        self._say(f"  {f.id} pod {cid[:12]} torn down")

    @staticmethod
    def _signature(e: BaseException) -> str:
        """What "failed the same way" means. Class plus the head of the message."""
        return f"{type(e).__name__}: {str(e)[:160]}".replace("\n", " ")

    def _record_harness_failure(self, f: Finding, e: BaseException,
                                elapsed: float) -> None:
        """A stage raised. Name it, attach the traceback, and bound the retry.

        This path never builds a StageResult, so nothing here flows through the
        normal dispatch below — which is why the closed set used to have a hole
        precisely at infrastructure failure. The outcome is recorded on an artifact
        so it is queryable the same way every other outcome is.

        `patch_evaluated` is False on BOTH outcomes, unconditionally. An
        infrastructure failure must never be reportable as a verdict on the patch,
        and the state is STATE_FAILED, never STATE_REJECTED: a rejection is a
        judgement, and nothing here judged anything.
        """
        tb = traceback.format_exc(limit=6)
        sig = self._signature(e)

        prev = ""
        for line in (f.error or "").splitlines():
            if line.startswith(_SIG_PREFIX):
                prev = line[len(_SIG_PREFIX):].strip()
                break
        same = bool(prev) and prev == sig

        retryable = (isinstance(e, _RETRY_ONCE)
                     and not isinstance(e, _NEVER_RETRY))
        # AT MOST ONE. Not "fewer than max_attempts" — one. A second failure of the
        # same class has already told us what the first one could not.
        grant = retryable and f.attempts == 0 and not same

        outcome = (outcomes_mod.HARNESS_RAISED_RETRYING if grant
                   else outcomes_mod.INFRASTRUCTURE_FAILURE)
        self.store.add_artifact(
            f.id, kind="harness_failure", stage=f.stage, content=tb,
            meta={
                "outcome": outcome,
                "patch_evaluated": False,
                "exception": type(e).__name__,
                "signature": sig,
                "attempt": f.attempts + 1,
                "retryable_class": retryable,
                "retry_granted": grant,
                "same_failure_as_previous_attempt": same,
                "previous_signature": prev or "(none)",
                "what_this_is_not": (
                    "This is the harness failing, not a verdict on the patch. The "
                    "fix was not evaluated. Do not read this as evidence that the "
                    "patch is wrong, or that the bug does not reproduce."),
            })

        error_text = f"{_SIG_PREFIX}{sig}\n{tb}"
        if grant:
            self.store.update(f.id, state=STATE_PENDING, attempts=f.attempts + 1,
                              error=error_text)
            self.store.log(f.id, f.stage, "error",
                           f"[{outcome}] {sig} — one retry granted", elapsed)
            self._say(f"  {f.id} {f.stage}: raised ({sig}) — one retry granted")
        else:
            self.store.update(f.id, state=STATE_FAILED, attempts=f.attempts + 1,
                              error=error_text)
            why = ("same failure on attempt 2" if same
                   else "not a retryable class" if not retryable
                   else "retry already spent")
            self.store.log(f.id, f.stage, "fail", f"[{outcome}] {sig} — {why}",
                           elapsed)
            self._say(f"  {f.id} {f.stage}: INFRASTRUCTURE FAILURE ({sig}) — {why}; "
                      f"the patch was NOT evaluated")

    def unblock(self, finding_id: str, note: str = "") -> bool:
        """Return a blocked finding to the queue after a human has looked."""
        f = self.store.get(finding_id)
        if f is None or f.state != STATE_BLOCKED:
            return False
        self.store.update(finding_id, state=STATE_PENDING, attempts=0, error="")
        self.store.log(finding_id, f.stage, "unblocked", note)
        return True
