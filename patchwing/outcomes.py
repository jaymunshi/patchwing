"""The closed set of outcome values.

Every terminating path in ``stages.py`` — every ``return StageResult.*`` — carries
exactly one value from this module, and no two paths carry the same one. That pair
of properties is what makes an outcome readable as evidence: a value in a package
names the *place the run stopped*, not a category someone invented at the call site.

Why a closed set rather than free strings
-----------------------------------------
A free string makes a typo a NEW CATEGORY. ``"verify_geen"`` would be emitted, stored,
and rendered without complaint, and the only signal would be a reader noticing an odd
word months later. Closed, a typo is a FAILURE: the value is not in ``ALL``, the guard
in ``tests/test_outcome_coverage.py`` fails, and the run never starts.

``ALL`` is derived from this module's own constants rather than retyped, because a
hand-maintained second list is a place to forget. Adding a constant is the only way
to widen the set, and the guard rejects any constant that no path uses — so the set
and the path list are held equal from both directions.

Runtime validation exists too (``StageResult.__post_init__``) but it is NOT the
enforcement. ``runner._advance`` catches broad ``Exception`` and converts it to a
RETRY, so a raise here would be swallowed into the retry loop and burn attempts
quietly. The static guard is the mechanism that actually cannot be talked around.

Naming: ``<stage>_<what happened>``. The two build outcomes keep their original,
un-prefixed names because the separation they encode is asserted by name elsewhere
and renaming would silently weaken those assertions.
"""

from __future__ import annotations

# --- decorator ------------------------------------------------------------
# The cost ceiling, tripped inside any stage. Not stage-specific by construction.
CEILING_EXCEEDED = "ceiling_exceeded"

# --- ingest ---------------------------------------------------------------
INGEST_MISSING_FIELDS = "ingest_missing_fields"
INGEST_NOTHING_TO_LOCALIZE = "ingest_nothing_to_localize"
INGEST_ACCEPTED = "ingest_accepted"

# --- localize -------------------------------------------------------------
LOCALIZE_SUPPLY_CHAIN_ADVISORY = "localize_supply_chain_advisory"
LOCALIZE_UPSTREAM_FIX_UNRESOLVED = "localize_upstream_fix_unresolved"
LOCALIZE_FROM_UPSTREAM_FIX = "localize_from_upstream_fix"
LOCALIZE_NO_SPEC = "localize_no_spec"
LOCALIZE_NO_MODEL_CONFIGURED = "localize_no_model_configured"
LOCALIZE_SYMPTOM_FAILED = "localize_symptom_failed"
LOCALIZE_BY_SYMPTOM = "localize_by_symptom"
LOCALIZE_DECLARED_FILES_MISSING = "localize_declared_files_missing"
LOCALIZE_FROM_SPEC = "localize_from_spec"

# --- provision (Pass 2) ---------------------------------------------------
# Real body outcomes shipped in Step 5. The Step 2 placeholder outcome
# (provision_placeholder) is deliberately NOT declared here — the closed
# set only names live paths; historical audit rows with that value stay
# readable but no NEW writes can use it.
PROVISION_SHORTCIRCUIT = "provision_shortcircuit"
PROVISION_NO_DRAFT_SPEC = "provision_no_draft_spec"
PROVISION_DRAFT_UNREADABLE = "provision_draft_unreadable"
PROVISION_NO_MODEL_CONFIGURED = "provision_no_model_configured"
PROVISION_NO_BUDGET = "provision_no_budget"
PROVISION_POD_PREP_FAILED = "provision_pod_prep_failed"
PROVISION_BUDGET_EXHAUSTED = "provision_budget_exhausted"
# --- recursive provision loop (2026-08-08) ---
# Fires when the outer loop exhausts turns/USD while any binary
# check is still failing. Preserves the last check's failure tail
# in the finding's error message; worker survives.
PROVISION_LOOP_EXHAUSTED = "provision_loop_exhausted"
# Bootstrap phase (deterministic pod setup BEFORE first model turn)
# failed. Ecosystem-specific: install base tools, clone source,
# install node at derived major, install target, workspace deps.
# If any step returns non-zero, the loop refuses to start.
PROVISION_BOOTSTRAP_FAILED = "provision_bootstrap_failed"
# No-progress guard: same (check_name, exit_code, tail_hash)
# signature seen K consecutive times → abort as stuck rather
# than burning to max_turns on the same failure.
PROVISION_LOOP_STUCK = "provision_loop_stuck"
PROVISION_GAVE_UP = "provision_gave_up"
PROVISION_COMMIT_FAILED = "provision_commit_failed"
PROVISION_INVALID_SPEC = "provision_invalid_spec"
PROVISION_COMPLETE = "provision_complete"

# Pass 5 — preferred_template consumption. Distinct outcomes per failure
# mode so a reader knows exactly which trust boundary broke. Silent
# fallback would be the ARVO-answer-key drift wearing a new coat.
PROVISION_TEMPLATE_MISSING = "provision_template_missing"
PROVISION_TEMPLATE_IMAGE_GONE = "provision_template_image_gone"
PROVISION_TEMPLATE_DIGEST_DRIFT = "provision_template_digest_drift"

# --- reproduce ------------------------------------------------------------
REPRODUCE_NEEDS_EXECUTION_PLANE = "reproduce_needs_execution_plane"
REPRODUCE_NO_SPEC = "reproduce_no_spec"
REPRODUCE_NO_COMMAND = "reproduce_no_command"
REPRODUCE_PREBUILD_FAILED = "reproduce_prebuild_failed"
REPRODUCE_TIMEOUT = "reproduce_timeout"
REPRODUCE_DID_NOT_REPRODUCE = "reproduce_did_not_reproduce"
REPRODUCE_WALL_NOT_ESTABLISHED = "reproduce_wall_not_established"
REPRODUCE_WALL_HAS_NO_REPRODUCER = "reproduce_wall_has_no_reproducer"
# The reproduce command fails the wall's shape check (wall.validate_command_shape):
# it embeds inline shell body / a metacharacter, or it runs no file in the frozen
# reproducer set. A spec defect, NOT infrastructure and NOT a verdict on any patch
# (patch_evaluated=False) — the wall refuses to establish because a command whose
# logic is not in a frozen file could be rewritten undetected.
REPRODUCE_COMMAND_SHAPE_INVALID = "reproduce_command_shape_invalid"
REPRODUCE_RED_CONFIRMED = "reproduce_red_confirmed"
# §6b′: neither red nor green. These exist so a malfunction can never be recorded
# as "the bug reproduced" on a target whose pristine exit code is 1.
REPRODUCE_DIFFERENT_BUG = "reproduce_different_bug"
REPRODUCE_HARNESS_FAULT = "reproduce_harness_fault"

# --- patch ----------------------------------------------------------------
PATCH_NO_SPEC = "patch_no_spec"
PATCH_NO_LOCALIZATION = "patch_no_localization"
PATCH_LOCALIZATION_EMPTY = "patch_localization_empty"
PATCH_NO_REPRODUCER_LOCK = "patch_no_reproducer_lock"
PATCH_LOCK_UNREADABLE = "patch_lock_unreadable"
PATCH_TARGET_FROZEN = "patch_target_frozen"
PATCH_TARGET_INSIDE_WALL = "patch_target_inside_wall"
PATCH_SOURCE_UNREADABLE_IN_IMAGE = "patch_source_unreadable_in_image"
PATCH_SOURCE_UNREADABLE_ON_HOST = "patch_source_unreadable_on_host"
PATCH_AUTH_CONFIG_ERROR = "patch_auth_config_error"
PATCH_MODEL_CALL_FAILED = "patch_model_call_failed"
PATCH_MODEL_CLIENT_UNAVAILABLE = "patch_model_client_unavailable"
PATCH_DID_NOT_APPLY = "patch_did_not_apply"
# The model returned `edits` as a non-string (list, dict, int, …) — a schema
# violation, not an ambiguity. Terminal, patch_evaluated=False, NO auto-retry.
# A model that returned `[]` once will very likely return `[]` again; the fix
# for this class of failure lives in the prompt, not in a retry loop. If we
# later decide to retry with a "the edits field must be a string" note, add
# PATCH_EDITS_WRONG_TYPE_ON_RETRY as its sibling then.
PATCH_EDITS_WRONG_TYPE = "patch_edits_wrong_type"
# --- retry-on-ambiguous-SEARCH terminal paths ------------------------------
# The stage catches AmbiguousSearchError specifically and re-invokes the same
# model once with the exact validator message (parallel to models.chat_json's
# JSON-repair loop). Each of the four terminal ways that retry can end gets its
# own outcome — the outcome-uniqueness guard is deliberate: "auth failed on
# the first call" and "auth failed on the retry" are two distinct ways of
# stopping, and a reader who cannot tell them apart cannot tell whether the
# problem is a bad config or a mid-flight endpoint change.
PATCH_AMBIGUOUS_AFTER_RETRY = "patch_ambiguous_after_retry"
# The multi-turn investigation loop hit its turn or USD budget cap before
# the reproducer went green. Terminal, no auto-retry — a model that couldn't
# converge on a fix within the budget won't converge in another equal one
# spent the same way. Loop is reproducer-only (no answer-key comparison); a
# budget-exhausted verdict is a real failure signal, not a harness fault.
PATCH_INVESTIGATION_EXHAUSTED = "patch_investigation_exhausted"
# Model explicitly declared it cannot fix the bug (returned `give_up` with a
# reason). Distinct from budget-exhausted so the paper can separate "we ran
# out of budget" from "the model recognized its own limits."
PATCH_INVESTIGATION_GAVE_UP = "patch_investigation_gave_up"
# The patch stage spawned a child investigation because the patch closed the
# original bug but exposed a NEW downstream crash (four_state=different_bug),
# and the child failed to close that new crash within its own budget. Parent
# is rejected — the fix introduces an unfixed downstream defect.
PATCH_INVESTIGATION_CHILD_FAILED = "patch_investigation_child_failed"
# Recursion cap tripped: patch → different_bug → child patch → different_bug →
# ... beyond [fix_writer].investigation_max_recursion_depth (default 2). Fail
# honestly rather than let cascading downstream bugs run unbounded.
PATCH_INVESTIGATION_RECURSION_DEPTH_EXCEEDED = "patch_investigation_recursion_depth_exceeded"
PATCH_DID_NOT_APPLY_ON_RETRY = "patch_did_not_apply_on_retry"
# Sibling of PATCH_EDITS_WRONG_TYPE for the retry-parse call site — the
# ambiguity retry loop also calls edit.parse a second time, and the guard
# requires each terminating code path to carry a distinct outcome.
PATCH_EDITS_WRONG_TYPE_ON_RETRY = "patch_edits_wrong_type_on_retry"
PATCH_AUTH_CONFIG_ERROR_ON_RETRY = "patch_auth_config_error_on_retry"
PATCH_MODEL_CALL_FAILED_ON_RETRY = "patch_model_call_failed_on_retry"
PATCH_DIFF_TOO_LARGE = "patch_diff_too_large"
PATCH_WRITTEN = "patch_written"

# --- verify ---------------------------------------------------------------
# There is deliberately no bare `verify_green` any more. Once the rollback leg
# exists, "the reproducer passed" is no longer a terminal claim — it is half of
# one. A green that was never rolled back has not shown the diff was load-bearing,
# and saying only "green" would let the weaker result wear the stronger result's
# name. The four VERIFY_GREEN_ROLLBACK_* values below are the terminal claims, and
# VERIFY_GREEN_ROLLBACK_RED is the one the milestone exists to produce.
VERIFY_NO_SPEC = "verify_no_spec"
VERIFY_NO_PATCH_ARTIFACT = "verify_no_patch_artifact"
VERIFY_PATCH_STALE = "verify_patch_stale"
VERIFY_PATCH_NAMES_NO_FILE = "verify_patch_names_no_file"
VERIFY_NO_REPRODUCER_LOCK = "verify_no_reproducer_lock"
VERIFY_LOCK_UNREADABLE = "verify_lock_unreadable"
VERIFY_PRE_PATCH_UNREADABLE = "verify_pre_patch_unreadable"
VERIFY_WALL_VIOLATED_BEFORE_BUILD = "verify_wall_violated_before_build"
# Kept un-prefixed deliberately: the timeout/compile-failure separation is asserted
# by literal name in tests/test_outcomes.py. A timeout is ABSENCE (the patch was
# never judged); a compile failure is a JUDGEMENT (the patch is not valid code).
BUILD_TIMEOUT_KILL = "build_timeout_kill"
BUILD_COMPILE_FAILURE = "build_compile_failure"
# The 1076 CDATA run revealed this: `arvo compile` inside a prebuilt-only image
# can fail before the compiler ever gets to the patched source (configure error,
# missing toolchain, cannot-run-C-programs). That is NOT a verdict on the patch;
# it is the harness failing. Under the old code it read as build_compile_failure
# ("the patch is not valid code"), which claims something the run never learned.
# patch_evaluated is False here without exception.
VERIFY_BUILD_HARNESS_FAULT = "verify_build_harness_fault"
VERIFY_WALL_VIOLATED_DURING_EXECUTION = "verify_wall_violated_during_execution"
VERIFY_REPRODUCER_TIMEOUT = "verify_reproducer_timeout"
VERIFY_FIX_DID_NOT_RESOLVE = "verify_fix_did_not_resolve"
VERIFY_SUITE_BROKEN = "verify_suite_broken"
# §6b′ at the verify leg. A patched tree that crashes DIFFERENTLY has not been
# fixed, and it has not failed in the way the reproducer describes either.
VERIFY_DIFFERENT_BUG = "verify_different_bug"
VERIFY_HARNESS_FAULT = "verify_harness_fault"

# --- rollback leg (§6) -----------------------------------------------------
# Rollback is EVIDENCE, not a gate. Green-then-not-red indicts the UNDO MECHANISM
# or the ORACLE — never the patch, which has already been verified by this point.
# So these are all OK-status outcomes: the verdict on the patch stands, and what
# the rollback showed is reported alongside it rather than overriding it.
VERIFY_GREEN_ROLLBACK_RED = "verify_green_rollback_red"
VERIFY_GREEN_ROLLBACK_NOT_RED = "verify_green_rollback_not_red"
VERIFY_GREEN_ROLLBACK_UNDO_BROKEN = "verify_green_rollback_undo_broken"
VERIFY_GREEN_ROLLBACK_BUILD_FAILED = "verify_green_rollback_build_failed"

# --- package --------------------------------------------------------------
PACKAGE_MISSING_INPUTS = "package_missing_inputs"
PACKAGE_NO_REPRODUCER_LOCK = "package_no_reproducer_lock"
PACKAGE_ASSEMBLED = "package_assembled"

# --- review ---------------------------------------------------------------
REVIEW_AWAITING_HUMAN = "review_awaiting_human"

# --- harness ---------------------------------------------------------------
# Recorded by runner._advance, NOT by a stage. A stage that raises never builds a
# StageResult, so before these existed the closed set had a hole exactly where the
# infrastructure fails: the finding went to STATE_FAILED carrying a traceback and no
# outcome at all, which is the same shape as a run that WAS judged and found wanting.
# The probe found that, not either of us reasoning about it.
#
# Both carry patch_evaluated=False without exception. AN INFRASTRUCTURE FAILURE MUST
# NEVER BE REPORTABLE AS A VERDICT ON THE PATCH — the fourth instance of one disease,
# after timeout/compile, exit-1/harness-fault, and rollback-satisfied-by-malfunction.
HARNESS_RAISED_RETRYING = "harness_raised_retrying"
INFRASTRUCTURE_FAILURE = "infrastructure_failure"

# --- pod-per-finding lifecycle --------------------------------------------
# The VM restarted (or the pod died) between iterations. The chain of custody
# for THIS finding is broken — the pristine token was recorded against a pod
# that no longer exists, and a fresh compile could reproduce a different
# DEDUP_TOKEN or hit a different region (1076 pristine is 3/5 vs 2/5). Do not
# offer resume; do not silently re-create. Mark terminal and let the user
# start a fresh finding with the same spec.
POD_LOST_AT_REPRODUCE = "pod_lost_at_reproduce"
POD_LOST_AT_PATCH = "pod_lost_at_patch"
POD_LOST_AT_VERIFY = "pod_lost_at_verify"
# The revert-then-iterate wall assertion (assertion (a): patched file reverted
# only) failed — the file did not match its pre-patch hash. Refuse to iterate
# on a dirty tree; something drifted.
ITERATE_STATE_DIRTY = "iterate_state_dirty"



# --- patch (ecosystem-aware) ---
PATCH_NO_PATCHABLE_SOURCE            = "patch_no_patchable_source"

# --- provision (ecosystem) ---
PROVISION_NO_ECOSYSTEM_STRATEGY      = "provision_no_ecosystem_strategy"
PROVISION_STRATEGY_PREREQS_MISSING   = "provision_strategy_prereqs_missing"
PROVISION_STRATEGY_SCOPE_EXCEEDED    = "provision_strategy_scope_exceeded"
PROVISION_REPRODUCER_INVALID         = "provision_reproducer_invalid"

# --- harness safety-degrade ---
HARNESS_UNKNOWN_OUTCOME              = "harness_unknown_outcome"


ALL: frozenset[str] = frozenset(
    v for k, v in list(globals().items())
    if k.isupper() and not k.startswith("_") and isinstance(v, str)
)



class UnknownOutcome(ValueError):
    """An outcome value that is not in the closed set.

    A programming error, never a transient. Raised at StageResult construction so
    the bad value cannot reach the store or a package.
    """


def validate(value: str) -> str:
    """Return ``value`` if it is in the closed set, else return the safe-degrade
    sentinel ``HARNESS_UNKNOWN_OUTCOME`` and emit a stderr warning.

    Doctrine (handoff): a dead worker strands the finding and poisons the queue
    for every following finding in a live run. "Fail loud" means a VISIBLE
    VERDICT (FAILED state + error message + fail log), NOT a dead thread.
    Loud != crash.

    This function is TOTAL — it never raises. If the caller supplies an outcome
    string that is not in ALL:
      * the returned sentinel routes the StageResult through the normal FAIL
        path (state=FAILED, error preserved, pod torn down, worker survives)
      * meta['outcome_original'] preserves the intended (unregistered) name for
        audit and grep
      * a stderr WARNING names the missed outcome so developers see it in
        journalctl and CI (see tests/test_outcome_coverage.py — the STATIC
        guard that catches this before it reaches runtime)

    The static guard in tests/test_outcome_coverage.py is the PRIMARY
    enforcement. This function is the runtime SAFETY NET that ensures a slip
    past CI is still SAFE.

    ``UnknownOutcome`` class is preserved for import compatibility with any
    external caller. Nothing in-tree raises it after this refactor.
    """
    if value in ALL:
        return value
    import sys as _sys
    _sys.stderr.write(
        f"WARNING [outcomes.validate]: {value!r} is not a declared outcome. "
        f"Degrading to HARNESS_UNKNOWN_OUTCOME. Add {value!r} to "
        f"patchwing/outcomes.py; the CI guard "
        f"(tests/test_outcome_coverage.py) should have caught this before "
        f"runtime.\n")
    _sys.stderr.flush()
    return HARNESS_UNKNOWN_OUTCOME
