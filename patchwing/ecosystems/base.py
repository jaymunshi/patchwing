"""EcosystemStrategy — abstract contract for ecosystem-specific behavior.

Core stages (provision, verify) call this interface only. Concrete strategies
(npm, pip, maven, ...) live as sibling modules and register via @register().

Two exceptions callers must handle:
  - UnknownEcosystem: no strategy registered for a given name
  - EcosystemScopeExceeded: a strategy could not handle a target's specific
    shape (e.g. no scripts.build, custom bundler layout the strategy can't
    map). Provision converts these to fail-loud blocks with an explicit
    reason — never silent mis-mapping.

Invariants (checked or documented per method):
  * Every path returned is an in-pod ABSOLUTE path
  * build_command output MUST work under network=none (hermeticity enforced
    by the verify sandbox, NOT by any --offline flag)
  * installed_dist_root returns a DIRECTORY (attestation is a manifest of
    file hashes over that directory)
  * Strategies are stateless — all context comes from (sb, install_root)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class UnknownEcosystem(Exception):
    """Ecosystem name has no registered strategy. Callers must fail loud."""


class EcosystemScopeExceeded(Exception):
    """A registered strategy cannot handle this target's specific shape.
    Message names the exact reason (e.g. 'no scripts.build in package.json
    or root workspace'). Actionable: extend the strategy, add a variant,
    or park the finding."""


class EcosystemStrategy(ABC):
    """Contract every ecosystem strategy implements.

    Callers hold a strategy instance from `for_ecosystem(name)`. All
    per-target derivation happens inside the strategy — core stages
    never branch on ecosystem name.
    """

    #: Registry key. Must match `advisories.ecosystem` values.
    name: str = ""

    # ----- detection -----

    @abstractmethod
    def detect(self, sb, install_root: str, pkg_name: str) -> bool:
        """True if this strategy can handle the target. Reads the pod's
        own manifest/lockfile to confirm; never trusts the ecosystem
        hint alone. False means the caller must try another strategy or
        block the finding."""

    # ----- structural discovery (provision-time, network on) -----

    @abstractmethod
    def package_meta(self, sb, install_root: str, pkg_name: str) -> dict:
        """Return {name, version, entry_path, manifest_files, tool}.
        All derived from the pod's own package/lock files, never
        hardcoded per-target. Raises EcosystemScopeExceeded if the
        manifest lacks the needed fields."""

    @abstractmethod
    def source_root_in_pod(self, sb) -> str:
        """Absolute path in pod where the source clone lives (e.g.
        /pw/src/<pkg>). Convention declared by the strategy; provision
        writes the clone there. Raises EcosystemScopeExceeded if the
        expected clone is missing."""

    @abstractmethod
    def is_source_path_patchable(self, source_relpath: str,
                                  target_pkg_dir_in_source: str) -> bool:
        """Given a repo-relative source path (from localization) and the
        target package's directory within the source tree, return
        True if the patch stage should attempt to edit it. False for
        tests, docs, playgrounds, or files outside the target package."""

    # ----- lifecycle -----

    @abstractmethod
    def provision_prep_commands(self, sb, install_root: str,
                                 pkg_name: str) -> list[str]:
        """Shell commands to run at provision time (network available).
        Must leave the image in a state where verify's build succeeds
        HERMETICALLY (network=none). Provision runs a smoke build with
        network OFF after these commands complete; if it fails, the
        strategy's prep is incomplete."""

    @abstractmethod
    def build_command(self, sb, install_root: str, pkg_name: str) -> str:
        """The command verify runs (in network=none sandbox) after
        applying a patch. Must:
          - rebuild from the source clone
          - replace bytes at installed_dist_root() with fresh build output
          - exit non-zero on any failure
        Hermeticity is a SANDBOX property, not a build-flag property —
        do NOT include --offline or similar flags that rely on tool
        cooperation. Raises EcosystemScopeExceeded if the strategy
        cannot derive a build command from the target's config."""

    @abstractmethod
    def incremental_build_command(self, sb, install_root: str,
                                   pkg_name: str) -> Optional[str]:
        """Optional fast-path for subsequent patch iterations. Same
        hermeticity contract. Return None if the target has no
        incremental build."""

    # ----- attestation -----

    @abstractmethod
    def version_pin_files(self, sb, install_root: str,
                           pkg_name: str) -> list[str]:
        """Absolute in-pod paths of files that pin the vulnerable
        version (e.g. package.json + lockfile). Added to
        spec.reproducer.files for wall freeze so 'patch-by-dep-bump'
        can't sneak past attestation."""

    @abstractmethod
    def source_clone_command(self, repo_url: str, pkg_name: str,
                              affected_ref: str) -> str:
        """Return the shell command that clones the target repo INTO
        /pw/src/<pkg_name>/ and checks out `affected_ref`. Executed by
        bootstrap BEFORE node is installed — must only use tools that
        exist in a bare Ubuntu (git, curl, sh, mkdir). Not optional.
        """
        raise NotImplementedError

    @abstractmethod
    def post_node_setup_commands(self, source_root: str, pkg_name: str,
                                    install_root: str,
                                    affected_ref: str) -> list[str]:
        """Return commands run AFTER node is installed. Each must exit 0
        or bootstrap fails the finding loud. Includes: verify target
        package.json, install target vulnerable version, sanity-check
        version, warm workspace tool (pnpm/yarn), install source-tree
        workspace deps so the hermetic smoke build has everything.
        """
        raise NotImplementedError

    @abstractmethod
    def expected_source_ref(self, affected_ref: str) -> str:
        """Return the git-ref STRING the source clone must be at for
        `affected_ref` (a bare-version like "4.5.10"). Called by the
        provision loop's source-ref check.

        Ecosystems that tag as `v<X.Y.Z>` return `f"v{affected_ref}"`;
        others (pypi has no universal git-tag convention) may return the
        raw version. If not derivable, raise ValueError — the loop will
        refuse to start with provision_strategy_prereqs_missing.

        Kept SEPARATE from recommended_affected_version so the
        version-derivation logic (semver-dec) stays orthogonal to the
        tag-format convention.
        """
        raise NotImplementedError

    @abstractmethod
    def installed_dist_root(self, sb, install_root: str,
                             pkg_name: str) -> str:
        """Absolute in-pod DIRECTORY the runtime loads from. The
        installed-dist manifest (recomputed at reproduce and verify) is
        the sanity check that a rebuild ran and something changed. Not
        used as a verdict gate (bundlers can produce byte-identical
        output on a valid fix that lands in a hashed chunk); the
        reproducer flip is the sole verdict."""
