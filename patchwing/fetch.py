"""
Resolve the upstream fix for a CVE — the repository-fetching localizer.

Given a promoted advisory (a CVE with an OSS repo), find the commit that fixed
it and pull its diff from GitHub. This does two jobs at once:

  * **Localization** — the files the real fix touched are the files that hold
    the flaw. Ground truth, not a heuristic guess.
  * **Ground truth** — the actual upstream patch, stored so a generated fix can
    later be scored against it (and so a backport has a source to adapt).

HTTP only (GitHub API), so it runs on the control plane without cloning or a
toolchain. Unauthenticated GitHub allows 60 requests/hour; set GITHUB_TOKEN (or
PATCHWING_GITHUB_TOKEN) to raise that.

Important: the reference patch is stored as its OWN artifact kind and is NOT fed
to the patch stage — otherwise the model would just copy it. It exists for
scoring and backporting, not for generation.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from . import feeds

GITHUB_API = "https://api.github.com"


class FetchError(Exception):
    pass


def _gh(path: str, timeout: int = 45) -> dict:
    headers = {"User-Agent": "patchwing-fetch/0.1",
               "Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("PATCHWING_GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(GITHUB_API + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 403 and "rate limit" in e.read().decode("utf-8", "replace").lower():
            raise FetchError("GitHub API rate limit hit (60/hr unauthenticated). "
                             "Set GITHUB_TOKEN to raise it.") from e
        raise FetchError(f"GitHub {path} -> HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise FetchError(f"GitHub unreachable: {e.reason}") from e


def parse_github_repo(url: str) -> tuple[str, str] | None:
    if not url or "github.com/" not in url:
        return None
    tail = url.split("github.com/", 1)[1].strip("/")
    parts = tail.split("/")
    if len(parts) < 2:
        return None
    return parts[0], parts[1].replace(".git", "").split("#")[0]


# Files that mark a commit as a release/version bump rather than a code fix.
_METADATA = (".xml", ".lock", ".gradle", ".sum", ".mod", ".cfg", ".ini", ".txt",
             ".md", ".rst", ".toml", ".json", ".yaml", ".yml", ".properties")
_METADATA_NAMES = ("changelog", "version", "release", "pom.xml", "package.json",
                   "package-lock.json", "yarn.lock", "go.mod", "go.sum", "gemfile")

# Source extensions worth patching.
_SOURCE_EXT = (".java", ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".c",
               ".cc", ".cpp", ".h", ".hpp", ".rb", ".php", ".cs", ".kt", ".scala",
               ".swift", ".m", ".ex", ".exs", ".clj")


def _is_source(path: str) -> bool:
    p = path.lower()
    base = p.rsplit("/", 1)[-1]
    if base in _METADATA_NAMES:
        return False
    return p.endswith(_SOURCE_EXT)


def _fix_commits_and_repo(cve: str) -> tuple[list[str], str]:
    """
    Collect candidate fix commits and a repo URL from OSV + GHSA aliases.

    GHSA *reference* commits usually point at the actual security fix, whereas
    an OSV GIT `fixed` event often points at the tagged release commit (a
    version bump). So reference commits are tried first.
    """
    ref_commits: list[str] = []
    git_fixed: list[str] = []
    repo = ""
    try:
        v = feeds._get_json(feeds.OSV_VULN_URL + cve)
    except feeds.FeedError:
        return [], repo

    sources = [v]
    for a in v.get("aliases") or []:
        if a.startswith("GHSA-"):
            try:
                sources.append(feeds._get_json(feeds.OSV_VULN_URL + a))
            except feeds.FeedError:
                pass

    for src in sources:
        for aff in src.get("affected") or []:
            for rng in aff.get("ranges") or []:
                if rng.get("type") == "GIT":
                    if rng.get("repo") and not repo:
                        repo = rng["repo"]
                    for ev in rng.get("events") or []:
                        if ev.get("fixed") and len(ev["fixed"]) >= 7:
                            git_fixed.append(ev["fixed"])
        for ref in src.get("references") or []:
            u = ref.get("url", "")
            if "github.com/" in u and "/commit/" in u:
                sha = u.rsplit("/commit/", 1)[1].split("?")[0].split("#")[0].strip("/")
                if len(sha) >= 7:
                    ref_commits.append(sha)
                    if not repo:
                        pr = parse_github_repo(u)
                        if pr:
                            repo = f"https://github.com/{pr[0]}/{pr[1]}"

    seen, ordered = set(), []
    for c in ref_commits + git_fixed:   # reference commits first
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered, repo


def resolve_fix(cve: str, repo_url: str = "", max_patch_bytes: int = 60000) -> dict:
    """
    Return the upstream fix for a CVE:
        {repo, owner, name, fix_commit, commit_url, message,
         changed_files[], reference_patch, test_files[]}
    or {error: ...}.
    """
    commits, osv_repo = _fix_commits_and_repo(cve)
    repo = osv_repo or repo_url
    gh = parse_github_repo(repo)
    if not gh:
        return {"error": f"no GitHub repository resolvable for {cve} "
                         f"(repo hint: {repo or 'none'})"}
    owner, name = gh
    if not commits:
        return {"error": f"no fix commit found for {cve} in {owner}/{name} — "
                         f"OSV/GHSA list a fixed version but no commit"}

    # Fetch a bounded set of candidates and pick the one that actually changes
    # source code, preferring the most focused (fewest files). A commit that
    # touches only build/metadata files is a version bump, not the fix.
    last_err = ""
    best = None
    for sha in commits[:6]:
        try:
            c = _gh(f"/repos/{owner}/{name}/commits/{sha}")
        except FetchError as e:
            last_err = str(e)
            continue
        files = c.get("files") or []
        if not files:
            continue
        changed = [f["filename"] for f in files]
        src = [f for f in changed if _is_source(f)]
        cand = {"sha": sha, "commit": c, "files": files,
                "changed": changed, "src": src}
        if not src:
            best = best or ("weak", cand)          # version bump — last resort
            continue
        # a focused source commit is what we want; smaller is better
        score = (len(src) == 0, len(changed))       # source first, then fewer files
        if best is None or best[0] == "weak" or score < best[0]:
            best = (score, cand)
            # a tight source commit (<= 8 files) is good enough; stop early
            if len(changed) <= 8:
                break

    if best is None:
        return {"error": f"could not fetch a fix commit for {cve} "
                         f"({owner}/{name}): {last_err or 'no files in commits'}"}

    cand = best[1]
    files, changed, src = cand["files"], cand["changed"], cand["src"]
    version_only = not src
    parts, size = [], 0
    for f in files:
        p = f.get("patch")
        if p:
            block = f"--- a/{f['filename']}\n+++ b/{f['filename']}\n{p}"
            if size + len(block) > max_patch_bytes:
                parts.append(f"… ({len(files)} files total; patch truncated)")
                break
            parts.append(block)
            size += len(block)
    return {
        "repo": f"https://github.com/{owner}/{name}",
        "owner": owner, "name": name,
        "fix_commit": cand["sha"],
        "commit_url": cand["commit"].get("html_url", ""),
        "message": (cand["commit"].get("commit", {}).get("message", "") or "").strip()[:400],
        "changed_files": changed,
        "source_files": src,
        "version_only": version_only,
        "reference_patch": "\n\n".join(parts),
        "test_files": [f for f in changed
                       if "test" in f.lower() or "spec" in f.lower()],
    }
