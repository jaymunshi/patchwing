"""NpmStrategy — first concrete EcosystemStrategy implementation.

Derives every path, build command, and toolchain choice from the target
package's OWN configuration (package.json / lockfile / tsconfig) in the
pod. No package names or repo layouts are hardcoded — the strategy runs
identically against any npm target following the shapes documented below.

Supported shapes:
  1. Single-package repo. package.json at repo root, scripts.build produces
     a dist output, one package installed to node_modules/<name>/.
  2. Workspace monorepo where target has standalone scripts.build.
  3. Workspace monorepo where target requires root-level scripts.build
     (root package.json declares workspaces covering the target).

Unsupported (fails loud via EcosystemScopeExceeded):
  * No scripts.build anywhere resolvable
  * No lockfile (hermeticity requires a locked build)
  * Ambiguous package name (multiple package.json with the same name in
    the source clone)
  * Custom bundler configs the strategy can't locate the output of
"""
from __future__ import annotations

import json
import shlex
import re
from typing import Optional

from . import register
from .base import EcosystemStrategy, EcosystemScopeExceeded


# Convention: provision writes the source clone here. Documented for GLM
# via PROVISION_SYSTEM.
_SOURCE_CLONE_ROOT_TEMPLATE = "/pw/src/{pkg}"


@register("npm")
class NpmStrategy(EcosystemStrategy):
    """npm/pnpm/yarn projects. All derivations from target's own config."""

    # ============================================================
    # detection
    # ============================================================

    def detect(self, sb, install_root: str, pkg_name: str) -> bool:
        if not (install_root and pkg_name):
            return False
        if not self._exists(sb, f"{install_root}/package.json"):
            return False
        installed_pj = f"{install_root}/node_modules/{pkg_name}/package.json"
        if not self._exists(sb, installed_pj):
            return False
        try:
            source_root = self.source_root_in_pod(sb)
        except EcosystemScopeExceeded:
            return False
        pj_path = self._locate_target_package_json(sb, source_root, pkg_name,
                                                    raise_on_miss=False)
        return pj_path is not None

    # ============================================================
    # structural discovery
    # ============================================================

    def package_meta(self, sb, install_root: str, pkg_name: str) -> dict:
        installed_pj = f"{install_root}/node_modules/{pkg_name}/package.json"
        pj = self._read_json(sb, installed_pj)
        source_root = self.source_root_in_pod(sb)
        src_pj_path = self._locate_target_package_json(sb, source_root, pkg_name)
        tool = self._read_tool(sb, source_root)
        entry = self._read_entry(pj)
        version_pins = self.version_pin_files(sb, install_root, pkg_name)
        return {
            "name": pkg_name,
            "version": pj.get("version", ""),
            "entry_path": entry,
            "manifest_files": version_pins,
            "tool": tool,
            "source_package_json": src_pj_path,
        }

    def source_root_in_pod(self, sb) -> str:
        # Convention: provision clones each npm package to /pw/src/<pkg>.
        # Runtime discovery: look for ANY directory under /pw/src/ that
        # contains a package.json — first hit wins for single-package
        # targets. Provision guarantees the layout; strategy just verifies.
        candidates = self._ls(sb, "/pw/src") if self._exists(sb, "/pw/src") else []
        for entry in candidates:
            candidate = f"/pw/src/{entry}"
            if self._exists(sb, f"{candidate}/package.json"):
                return candidate
        raise EcosystemScopeExceeded(
            "no source clone found under /pw/src/ containing package.json — "
            "provision must clone the source repo to /pw/src/<pkg>/")

    def is_source_path_patchable(self, source_relpath: str,
                                  target_pkg_dir_in_source: str) -> bool:
        rel = (source_relpath or "").strip().lstrip("/")
        if not rel:
            return False
        # Reject known-not-patchable prefixes (relative to repo root).
        # Match at any depth: 'packages/<pkg>/__tests__/foo.ts' rejects on
        # '__tests__' even though the prefix isn't at repo root.
        DENY = ("node_modules/", "dist/", "build/", "lib-cov/",
                "test/", "tests/", "__tests__/", "spec/", "specs/",
                ".github/", "playground/", "playgrounds/",
                "docs/", "doc/", "examples/", "example/",
                "e2e/", "benchmark/", "benchmarks/", "fixtures/")
        parts = rel.split("/")
        for i in range(len(parts)):
            segment = parts[i] + "/"
            if segment in DENY or (i == 0 and parts[i] + "/" in DENY):
                return False
            # Also match without trailing slash for file-name tests:
            if parts[i] in ("test.js", "test.ts") or parts[i].startswith("test.") \
                    or parts[i].endswith(".test.ts") or parts[i].endswith(".test.js") \
                    or parts[i].endswith(".spec.ts") or parts[i].endswith(".spec.js"):
                return False
        # Require the path lives inside the target package's directory.
        # target_pkg_dir_in_source is relative to source root (e.g.
        # "packages/<pkg>" for a monorepo, "" for single-package).
        pkg_dir = (target_pkg_dir_in_source or "").strip().strip("/")
        if pkg_dir:
            if not (rel == pkg_dir or rel.startswith(pkg_dir + "/")):
                return False
        return True

    # ============================================================
    # lifecycle
    # ============================================================

    def provision_prep_commands(self, sb, install_root: str,
                                 pkg_name: str) -> list[str]:
        source_root = self.source_root_in_pod(sb)
        tool = self._read_tool(sb, source_root)
        cmds = []
        # 1. Ensure tool available. Only npm ships with node:18 by default;
        # pnpm and yarn need install.
        if tool == "pnpm":
            cmds.append("command -v pnpm >/dev/null 2>&1 || npm install -g pnpm")
        elif tool == "yarn":
            cmds.append("command -v yarn >/dev/null 2>&1 || npm install -g yarn")
        # 2. Install source-tree deps with frozen lockfile — populates
        # node_modules AND the tool's global cache so verify's networkless
        # build has everything it needs.
        install_cmd = {
            "pnpm": "pnpm install --frozen-lockfile",
            "yarn": "yarn install --frozen-lockfile",
            "npm":  "npm ci",
        }[tool]
        cmds.append(f"cd {shlex.quote(source_root)} && {install_cmd}")
        return cmds

    def build_command(self, sb, install_root: str, pkg_name: str) -> str:
        source_root = self.source_root_in_pod(sb)
        tool = self._read_tool(sb, source_root)
        src_pj_path = self._locate_target_package_json(sb, source_root, pkg_name)
        src_pkg_dir = src_pj_path.rsplit("/", 1)[0]
        # Determine which package.json's scripts.build runs and from which cwd.
        build_cwd, build_invocation = self._resolve_build(sb, source_root,
                                                           src_pj_path, tool)
        # Determine the dist-output directory the build writes.
        src_dist = self._read_source_dist_dir(sb, src_pj_path)
        # Where the runtime loads FROM — derived, not literal.
        dst_dist = self.installed_dist_root(sb, install_root, pkg_name)
        # NOTE: no --offline flag — hermeticity is a sandbox property
        # (network=none at verify). If the build tries to reach network,
        # the sandbox refuses and the build fails loud.
        return (
            f"set -euo pipefail && "
            f"cd {shlex.quote(build_cwd)} && "
            f"{build_invocation} && "
            f"rm -rf {shlex.quote(dst_dist)} && "
            f"mkdir -p {shlex.quote(dst_dist)} && "
            f"cp -r {shlex.quote(src_dist)}/. {shlex.quote(dst_dist)}/"
        )

    def incremental_build_command(self, sb, install_root: str,
                                   pkg_name: str) -> Optional[str]:
        source_root = self.source_root_in_pod(sb)
        src_pj_path = self._locate_target_package_json(sb, source_root, pkg_name)
        pj = self._read_json(sb, src_pj_path)
        scripts = pj.get("scripts") or {}
        for candidate in ("build:incremental", "dev-build", "build-dev"):
            if candidate in scripts:
                tool = self._read_tool(sb, source_root)
                src_pkg_dir = src_pj_path.rsplit("/", 1)[0]
                src_dist = self._read_source_dist_dir(sb, src_pj_path)
                dst_dist = self.installed_dist_root(sb, install_root, pkg_name)
                return (
                    f"set -euo pipefail && "
                    f"cd {shlex.quote(src_pkg_dir)} && "
                    f"{tool} run {shlex.quote(candidate)} && "
                    f"rm -rf {shlex.quote(dst_dist)} && "
                    f"mkdir -p {shlex.quote(dst_dist)} && "
                    f"cp -r {shlex.quote(src_dist)}/. {shlex.quote(dst_dist)}/"
                )
        return None

    # ============================================================
    # attestation
    # ============================================================

    def version_pin_files(self, sb, install_root: str,
                           pkg_name: str) -> list[str]:
        out = [f"{install_root}/package.json"]
        for lockname in ("pnpm-lock.yaml", "yarn.lock", "package-lock.json"):
            candidate = f"{install_root}/{lockname}"
            if self._exists(sb, candidate):
                out.append(candidate)
                break
        return out

    def installed_dist_root(self, sb, install_root: str,
                             pkg_name: str) -> str:
        installed_pj = f"{install_root}/node_modules/{pkg_name}/package.json"
        pj = self._read_json(sb, installed_pj)
        # Derive dist DIRECTORY from the installed package.json's own fields.
        # Order: main -> module -> exports."." -> files list. Take the
        # containing directory of the first shape-matching entry.
        for field in ("main", "module"):
            v = pj.get(field)
            if isinstance(v, str) and "/" in v:
                dir_rel = v.rsplit("/", 1)[0]
                return f"{install_root}/node_modules/{pkg_name}/{dir_rel}"
        exports = pj.get("exports") or {}
        if isinstance(exports, dict):
            dot = exports.get(".") if "." in exports else exports
            if isinstance(dot, dict):
                for key in ("import", "default", "require", "node"):
                    v = dot.get(key)
                    if isinstance(v, str) and "/" in v:
                        return (f"{install_root}/node_modules/{pkg_name}/"
                                f"{v.rsplit('/', 1)[0]}")
        files = pj.get("files")
        if isinstance(files, list):
            for f in files:
                if isinstance(f, str) and f.endswith("/"):
                    return (f"{install_root}/node_modules/{pkg_name}/"
                            f"{f.rstrip('/')}")
        raise EcosystemScopeExceeded(
            f"cannot derive installed dist directory from "
            f"{installed_pj} — package.json lacks a directory-shaped "
            f"main/module/exports/files hint. Strategy needs a variant "
            f"for this shape.")

    # ============================================================
    # internal helpers
    # ============================================================



    def recommended_affected_version(self, fixed_version: str) -> str | None:
        """HINT: last version < fixed_version, derived by semver-dec-1-patch.

        Returns None if the input isn't parseable semver, or if patch==0
        (decrementing minor requires an npm query for latest-patch which
        is out of scope for a pure derivation). Callers should verify the
        returned tag/version exists before using it — this is a hint, not
        a promise.

        Vite CVE example: fixed_version='4.5.11' → returns '4.5.10'.
        """
        if not fixed_version:
            return None
        s = str(fixed_version).lstrip("v").split("-", 1)[0].split("+", 1)[0]
        parts = s.split(".")
        if len(parts) < 3:
            return None
        try:
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        except (ValueError, TypeError):
            return None
        if patch > 0:
            return f"{major}.{minor}.{patch - 1}"
        return None

    def expected_source_ref(self, affected_ref: str) -> str:
        """npm ecosystem tags: `v<X.Y.Z>` (github convention for JS packages
        — vite@4.5.10 → git tag v4.5.10). Raises ValueError if the input
        is empty or not a semver-shaped string."""
        v = str(affected_ref or "").strip().lstrip("v")
        if not v:
            raise ValueError("expected_source_ref: affected_ref is empty")
        # Minimal shape check — not a full semver validator.
        if not re.match(r'^\d+\.\d+\.\d+([-+][A-Za-z0-9.-]+)?$', v):
            raise ValueError(f"expected_source_ref: {affected_ref!r} is not "
                             f"a semver-shaped string")
        return f"v{v}"

    def source_clone_command(self, repo_url: str, pkg_name: str,
                              affected_ref: str) -> str:
        """Single git command that clones the repo shallow at the affected
        tag. Called by bootstrap BEFORE node install. Uses only git+sh
        (present in bare Ubuntu after `apt-get install -y git`)."""
        import shlex
        source_root = f"/pw/src/{pkg_name}"
        tag = f"v{affected_ref.lstrip('v')}"
        return (
            f"mkdir -p {shlex.quote(source_root)} && "
            f"cd {shlex.quote(source_root)} && "
            f"git init -q && "
            f"git remote add origin {shlex.quote(repo_url)} && "
            f"git fetch --depth=1 origin refs/tags/{tag}:refs/tags/{tag} && "
            f"git checkout {tag} && "
            f"git log --oneline -1"
        )

    def post_node_setup_commands(self, source_root: str, pkg_name: str,
                                    install_root: str,
                                    affected_ref: str) -> list[str]:
        """Sequence run AFTER node/npm are installed. Every command must
        exit 0 — bootstrap fails loud on the first non-zero.

        Steps: verify target package.json → install target vulnerable
        version → sanity-check installed version → warm workspace tool
        globally (pnpm/yarn) → install source-tree workspace deps so
        the hermetic smoke build can find rollup/typescript/etc."""
        import shlex
        return [
            # 1. Verify: find /pw/src/<pkg>/**/package.json with matching name
            f"find {shlex.quote(source_root)} -type f -name package.json "
            f"-not -path '*/node_modules/*' "
            f"-exec sh -c 'python3 -c \"import json,sys; "
            f"d=json.load(open(sys.argv[1])); "
            f"print(sys.argv[1], d.get(chr(110)+chr(97)+chr(109)+chr(101)))\" "
            f"{{}} 2>/dev/null' \\; | grep {shlex.quote(pkg_name)} | head -3",
            # 2. Install target vulnerable version into install_root
            f"mkdir -p {shlex.quote(install_root)} && "
            f"cd {shlex.quote(install_root)} && "
            f"(test -f package.json || npm init -y) && "
            f"npm install {shlex.quote(pkg_name + '@' + affected_ref)} "
            f"2>&1 | tail -10",
            # 3. Sanity: installed version matches
            f"cat {shlex.quote(install_root)}/node_modules/{pkg_name}/package.json | "
            f"python3 -c \"import json,sys; d=json.load(sys.stdin); "
            f"assert d['version']=={shlex.quote(affected_ref)!r}, "
            f"'installed vs affected mismatch: '+d['version']+' vs '+{shlex.quote(affected_ref)!r}; "
            f"print('OK installed version matches: '+d['version'])\"",
            # 4. Workspace-tool warmer (global install; source-tree pnpm
            #    install is step 5). Detects via source lockfiles.
            f"if [ -f {shlex.quote(source_root)}/pnpm-workspace.yaml ] || "
            f"[ -f {shlex.quote(source_root)}/pnpm-lock.yaml ]; then "
            f"npm install -g pnpm && pnpm --version; "
            f"elif [ -f {shlex.quote(source_root)}/yarn.lock ]; then "
            f"npm install -g yarn && yarn --version; "
            f"else echo 'workspace tool: default npm (no pnpm/yarn lockfile)'; fi",
            # 5. Source-tree workspace deps — the piece r3 discovered was
            #    missing. Populates node_modules/.bin/{rollup,tsc,...}
            #    so the hermetic smoke build has every executable.
            f"cd {shlex.quote(source_root)} && "
            f"if [ -f pnpm-workspace.yaml ] || [ -f pnpm-lock.yaml ]; then "
            f"pnpm install --shamefully-hoist 2>&1 | tail -20; "
            f"elif [ -f yarn.lock ]; then "
            f"yarn install --frozen-lockfile 2>&1 | tail -20; "
            f"else npm install 2>&1 | tail -20; fi",
        ]

    def initial_setup_commands(self, repo_url: str, pkg_name: str,
                                install_root: str,
                                fixed_version: str) -> list[str] | None:
        """Concrete shell commands provision must run BEFORE authoring
        the reproducer. Version-pinned in BOTH the git checkout and the
        npm install so the source tree matches the installed package.

        Returns None if version pinning is not derivable — caller must
        explain to the model that manual version resolution is needed.
        """
        import shlex
        affected = self.recommended_affected_version(fixed_version)
        if not affected:
            return None
        source_root = f"/pw/src/{pkg_name}"
        return [
            # 1. Clone source repo — --depth 1 with tag ref for speed.
            f"mkdir -p {shlex.quote(source_root)} && "
            f"cd {shlex.quote(source_root)} && "
            f"git init -q && "
            f"git remote add origin {shlex.quote(repo_url)} && "
            f"git fetch --depth=1 origin refs/tags/v{affected}:refs/tags/v{affected} && "
            f"git checkout v{affected} && "
            f"git log --oneline -1 && "
            f"cat package.json | head -20",
            # 2. Verify the target package's own package.json is at the expected version.
            # For monorepos, find the target sub-package. For single-package, top-level.
            f"find {shlex.quote(source_root)} -type f -name package.json "
            f"-not -path '*/node_modules/*' "
            f"-exec sh -c 'jq -r . {{}} 2>/dev/null | "
            f"python3 -c \"import json,sys; d=json.load(sys.stdin); "
            f"print({{}}, \\\"name=\\\"+str(d.get(chr(110)+chr(97)+chr(109)+chr(101))), "
            f"\\\"version=\\\"+str(d.get(chr(118)+chr(101)+chr(114)+chr(115)+chr(105)+chr(111)+chr(110))))\"' \\; "
            f"| grep {shlex.quote('name='+pkg_name)} | head -3",
            # 3. Install target vulnerable package into the install_root.
            f"mkdir -p {shlex.quote(install_root)} && "
            f"cd {shlex.quote(install_root)} && "
            f"(test -f package.json || npm init -y) && "
            f"npm install {shlex.quote(pkg_name + '@' + affected)} 2>&1 | tail -10",
            # 4. Sanity: installed version matches source-tree version.
            f"cat {shlex.quote(install_root)}/node_modules/{pkg_name}/package.json | "
            f"python3 -c \"import json,sys; d=json.load(sys.stdin); "
            f"assert d['version']=={shlex.quote(affected)!r}, "
            f"'installed vs affected mismatch: '+d['version']+' vs '+{shlex.quote(affected)!r}; "
            f"print('OK installed version matches: '+d['version'])\"",
            # 5. WORKSPACE-TOOL WARMER (2026-08-08): install pnpm/yarn
            #    globally if the source uses one. The hermetic smoke check
            #    at commit-time runs `<tool> --filter <pkg> run build` in a
            #    network=none sandbox; if the tool isn't in the committed
            #    image, that check trips 'command not found' and the loop
            #    wastes turns diagnosing it. Derived from the cloned
            #    source's own lockfiles — no per-target hardcoding.
            f"if [ -f {shlex.quote(source_root)}/pnpm-workspace.yaml ] || "
            f"[ -f {shlex.quote(source_root)}/pnpm-lock.yaml ]; then "
            f"npm install -g pnpm && pnpm --version; "
            f"elif [ -f {shlex.quote(source_root)}/yarn.lock ]; then "
            f"npm install -g yarn && yarn --version; "
            f"else echo 'workspace tool: default npm (no pnpm/yarn lockfile found)'; fi",
        ]

    def _exists(self, sb, path: str) -> bool:
        r = sb.run(f"test -e {shlex.quote(path)} && echo Y || echo N")
        return "Y" in (r.stdout or "")

    def _ls(self, sb, path: str) -> list[str]:
        r = sb.run(f"ls -1 {shlex.quote(path)} 2>/dev/null")
        return [ln for ln in (r.stdout or "").splitlines() if ln.strip()]

    def _read_json(self, sb, path: str) -> dict:
        r = sb.run(f"cat {shlex.quote(path)}")
        try:
            return json.loads(r.stdout or "{}")
        except json.JSONDecodeError as e:
            raise EcosystemScopeExceeded(
                f"cannot parse {path} as JSON: {e}") from e

    def _read_file_head(self, sb, path: str, lines: int = 100) -> str:
        r = sb.run(f"head -{int(lines)} {shlex.quote(path)}")
        return r.stdout or ""

    def _locate_target_package_json(self, sb, source_root: str,
                                     pkg_name: str,
                                     raise_on_miss: bool = True) -> Optional[str]:
        # find all package.json under source_root; grep for "name": "<pkg>"
        # (json syntax is tolerant enough; a false positive would need an
        # unrelated pkg.json string-including <name> — very rare).
        r = sb.run(
            f"find {shlex.quote(source_root)} -type f -name package.json "
            f"-not -path '*/node_modules/*' "
            f"| xargs grep -l "
            f"'\"name\"[[:space:]]*:[[:space:]]*\"{pkg_name}\"' 2>/dev/null")
        matches = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
        # Verify each candidate really has that name at top level (not a
        # nested dep declared as `"dependencies": {"<name>": "..."}` — grep
        # matches those too).
        confirmed = []
        for c in matches:
            try:
                pj = self._read_json(sb, c)
                if pj.get("name") == pkg_name:
                    confirmed.append(c)
            except Exception:
                continue
        if len(confirmed) == 1:
            return confirmed[0]
        if not confirmed:
            if raise_on_miss:
                raise EcosystemScopeExceeded(
                    f"no package.json with top-level name={pkg_name!r} under "
                    f"{source_root} — provision must clone the source repo "
                    f"containing this package")
            return None
        if raise_on_miss:
            raise EcosystemScopeExceeded(
                f"ambiguous package name — multiple package.json with "
                f"name={pkg_name!r}: {confirmed}")
        return None

    def _read_tool(self, sb, source_root: str) -> str:
        for lockname, tool in (("pnpm-lock.yaml", "pnpm"),
                                ("yarn.lock", "yarn"),
                                ("package-lock.json", "npm")):
            if self._exists(sb, f"{source_root}/{lockname}"):
                return tool
        raise EcosystemScopeExceeded(
            f"no lockfile in {source_root} — strategy requires a locked "
            f"build for hermeticity (accepts pnpm-lock.yaml, yarn.lock, "
            f"or package-lock.json)")

    def _read_entry(self, pj: dict) -> str:
        for field in ("main", "module"):
            v = pj.get(field)
            if isinstance(v, str) and v:
                return v
        exports = pj.get("exports") or {}
        if isinstance(exports, dict):
            dot = exports.get(".") if "." in exports else exports
            if isinstance(dot, dict):
                for key in ("import", "default", "require", "node"):
                    v = dot.get(key)
                    if isinstance(v, str):
                        return v
        return ""

    def _read_source_dist_dir(self, sb, src_pj_path: str) -> str:
        """Absolute in-pod directory the SOURCE build writes its dist to.
        Derived from the source package.json's own fields (same logic as
        installed_dist_root, applied to source root)."""
        pj = self._read_json(sb, src_pj_path)
        pkg_dir = src_pj_path.rsplit("/", 1)[0]
        for field in ("main", "module"):
            v = pj.get(field)
            if isinstance(v, str) and "/" in v:
                return f"{pkg_dir}/{v.rsplit('/', 1)[0]}"
        exports = pj.get("exports") or {}
        if isinstance(exports, dict):
            dot = exports.get(".") if "." in exports else exports
            if isinstance(dot, dict):
                for key in ("import", "default", "require", "node"):
                    v = dot.get(key)
                    if isinstance(v, str) and "/" in v:
                        return f"{pkg_dir}/{v.rsplit('/', 1)[0]}"
        files = pj.get("files")
        if isinstance(files, list):
            for f in files:
                if isinstance(f, str) and f.endswith("/"):
                    return f"{pkg_dir}/{f.rstrip('/')}"
        raise EcosystemScopeExceeded(
            f"cannot derive source dist directory from {src_pj_path}")



    def _is_workspace_member(self, sb, source_root: str,
                              target_pkg_dir_rel: str) -> bool:
        """True iff target_pkg_dir_rel (repo-relative dir containing the
        target package.json) matches any glob in the root package.json's
        `workspaces` list. Derived entirely from manifests; no hardcoding.

        `workspaces` shape: either a list of glob strings (npm/pnpm classic,
        yarn v1) or {"packages": [...]} (yarn extended form). Both handled."""
        import fnmatch
        root_pj_path = f"{source_root}/package.json"
        if not self._exists(sb, root_pj_path):
            return False
        root_pj = self._read_json(sb, root_pj_path)
        ws = root_pj.get("workspaces")
        globs: list[str] = []
        if isinstance(ws, list):
            globs = [g for g in ws if isinstance(g, str)]
        elif isinstance(ws, dict):
            pkgs = ws.get("packages")
            if isinstance(pkgs, list):
                globs = [g for g in pkgs if isinstance(g, str)]
        if not globs:
            return False
        # Also read pnpm-workspace.yaml if present (pnpm-specific override).
        if self._exists(sb, f"{source_root}/pnpm-workspace.yaml"):
            wsyaml = self._read_file_head(sb, f"{source_root}/pnpm-workspace.yaml", 40)
            # Very light parse: lines starting with "  - " under "packages:"
            for line in wsyaml.splitlines():
                s = line.strip()
                if s.startswith("- ") or s.startswith("-\""):
                    tok = s.lstrip("- ").strip("\"'")
                    if tok:
                        globs.append(tok)
        target = (target_pkg_dir_rel or "").strip("/")
        if not target:
            return False
        # Match target against each glob (workspaces globs match directories).
        for g in globs:
            g_norm = g.strip("/")
            if fnmatch.fnmatch(target, g_norm) or fnmatch.fnmatch(target + "/", g_norm):
                return True
            # Also match against parent directories if glob is "packages/*"
            # and target is exactly one dir under packages/.
            if fnmatch.fnmatch(target, g_norm.rstrip("/*") + "/*"):
                return True
        return False

    def _detect_yarn_variant(self, sb, source_root: str) -> str:
        """Return 'berry' if yarn v2+ (.yarnrc.yml or .yarn/releases/), else 'v1'.
        Called only when tool=='yarn'."""
        if self._exists(sb, f"{source_root}/.yarnrc.yml"):
            return "berry"
        if self._exists(sb, f"{source_root}/.yarn/releases"):
            return "berry"
        return "v1"

    def _workspace_scoped_build(self, sb, source_root: str, tool: str,
                                  pkg_name: str) -> str:
        """Return the tool-specific workspace-scoped build invocation. Called
        from _resolve_build when the target IS a workspace member."""
        import shlex
        n = shlex.quote(pkg_name)
        if tool == "pnpm":
            return f"pnpm --filter {n} run build"
        if tool == "npm":
            return f"npm run build --workspace={n}"
        if tool == "yarn":
            variant = self._detect_yarn_variant(sb, source_root)
            if variant == "berry":
                return f"yarn workspaces foreach --include {n} --topological run build"
            return f"yarn workspace {n} run build"
        # Unreachable — _read_tool restricts to the three above.
        raise EcosystemScopeExceeded(
            f"tool {tool!r} has no known workspace-scoped build invocation")

    def _resolve_build(self, sb, source_root: str, src_pj_path: str,
                        tool: str) -> tuple[str, str]:
        """Return (build_cwd, build_invocation).

        Chunk B priority (revised per handoff correction):
          1. Target IS a workspace member (root package.json declares
             workspaces covering it) → run tool-specific `--filter <name>`
             / `--workspace <name>` / `workspaces foreach --include <name>`
             from source_root. The tool resolves the sibling dep graph
             and builds workspace deps first; the target's own
             scripts.build alone might not do that in a monorepo.
          2. Target is NOT a workspace member AND has its own
             scripts.build → target-standalone build (single-package
             repos with scripts.build at their root).
          3. Else EcosystemScopeExceeded.

        Derivation is manifest-only: `workspaces` glob list from root
        package.json, plus target package.json's own `name`. Nothing
        hardcoded per-target."""
        import json
        pkg_dir = src_pj_path.rsplit("/", 1)[0]
        # Repo-relative dir of the target package (source_root is the repo root).
        target_pkg_dir_rel = pkg_dir[len(source_root):].lstrip("/") if pkg_dir.startswith(source_root) else pkg_dir
        src_pj = self._read_json(sb, src_pj_path)
        pkg_name = src_pj.get("name", "")
        if not pkg_name:
            raise EcosystemScopeExceeded(
                f"target package.json at {src_pj_path} has no `name` — "
                f"cannot form workspace-scoped build invocation")
        # Priority 1: workspace member
        if self._is_workspace_member(sb, source_root, target_pkg_dir_rel):
            invocation = self._workspace_scoped_build(sb, source_root, tool, pkg_name)
            return source_root, invocation
        # Priority 2: target-standalone (single-package)
        if isinstance(src_pj.get("scripts"), dict) and \
                src_pj["scripts"].get("build"):
            return pkg_dir, f"{tool} run build"
        # Priority 3: fail loud
        raise EcosystemScopeExceeded(
            f"no scripts.build resolvable — target {src_pj_path} "
            f"(pkg={pkg_name!r}, dir={target_pkg_dir_rel!r}) is not a "
            f"workspace member of {source_root} AND has no own "
            f"scripts.build. Strategy needs a variant for this shape.")
