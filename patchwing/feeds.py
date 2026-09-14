"""
Intake feeds — where the advisory list comes from.

Three no-key sources, joined into one deduped table:

  CISA KEV   the anchor: vulnerabilities *actively exploited in the wild*. This
             is also the EU CRA "actively exploited" trigger, so KEV membership
             is both the top priority signal and the regulatory-deadline set.
  EPSS       FIRST.org daily exploit-probability (0..1) — better ranking than
             CVSS, and CVSS is now often absent since NIST stopped enriching
             most CVEs in 2026.
  OSV.dev    maps a CVE to an OSS package, ecosystem, and FIXED VERSION. This is
             what tells us a finding is *actionable* — PatchWing patches source,
             so "has an OSS record with a fix" is the line between fixable and
             merely visible.

There is no push feed anywhere in this space; intake is polling deltas. Cadence
is matched to each source's real update rate (KEV changes a few times a week,
EPSS daily), so "new CVE → on the page" lands in minutes, not seconds.

Stdlib only. The control plane has network; this never runs in the sandbox.
"""

from __future__ import annotations

import gzip
import json
import time
import urllib.error
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

UA = "patchwing-intake/0.1 (+https://patchwing.dev)"

# Coarse platform buckets from vendor/product strings. OSS is decided by OSV,
# not by keywords — these only classify the non-OSS remainder.
_WINDOWS = ("microsoft", "windows", ".net", "azure", "sharepoint", "exchange server")
_APPLE = ("apple", "macos", "ios", "safari", "ipados", "watchos")
_NETWORK = ("cisco", "fortinet", "fortios", "palo alto", "pan-os", "ivanti",
            "citrix", "netscaler", "juniper", "sonicwall", "f5", "big-ip",
            "vpn", "router", "firewall", "zyxel", "netgear", "d-link")
_LINUX = ("linux", "kernel", "red hat", "redhat", "ubuntu", "debian", "suse",
          "centos")

# Advisories that have a "fixed version" but NO code vulnerability to patch:
# malicious publishes, typosquats, compromised accounts. The fix was removing
# malware and republishing, not changing a line of code. PatchWing cannot act on
# these — there is no diff to reason about — so they are never "actionable".
_SUPPLY_CHAIN = (
    "malware", "malicious code", "malicious version", "malicious package",
    "malicious dependency", "credential-steal", "credential steal", "exfiltrat",
    "backdoor", "typosquat", "supply chain", "supply-chain", "compromised",
    "protestware", "cryptominer", "crypto miner", "infostealer", "info-stealer",
    "info stealer", "trojan", "stealer", "account takeover of the",
)


def is_supply_chain(*texts: str) -> bool:
    hay = " ".join(t for t in texts if t).lower()
    return any(m in hay for m in _SUPPLY_CHAIN)


class FeedError(Exception):
    pass


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            return raw
    except urllib.error.HTTPError as e:
        raise FeedError(f"{url} -> HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise FeedError(f"{url} unreachable: {e.reason}") from e


def _get_json(url: str, timeout: int = 60) -> dict:
    return json.loads(_get(url, timeout).decode("utf-8", "replace"))


def classify(vendor: str, product: str, ecosystem: str) -> str:
    if ecosystem:
        return "oss"
    hay = f"{vendor} {product}".lower()
    for cat, needles in (("network", _NETWORK), ("windows", _WINDOWS),
                         ("apple", _APPLE), ("linux", _LINUX)):
        if any(n in hay for n in needles):
            return cat
    return "app"


# --------------------------------------------------------------------------
# CISA KEV — the anchor list
# --------------------------------------------------------------------------

def poll_kev(store) -> dict:
    data = _get_json(KEV_URL)
    vulns = data.get("vulnerabilities") or []
    now = time.time()
    conn = store.conn
    added = updated = 0

    for v in vulns:
        cve = v.get("cveID")
        if not cve:
            continue
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        row = conn.execute("SELECT cve, first_seen FROM advisories WHERE cve=?",
                           (cve,)).fetchone()
        fields = {
            "source": "kev",
            "vendor": vendor,
            "product": product,
            "title": v.get("vulnerabilityName", "") or f"{vendor} {product}",
            "description": v.get("shortDescription", ""),
            "category": classify(vendor, product, ""),
            "exploited": 1,
            "ransomware": 1 if str(v.get("knownRansomwareCampaignUse", "")).lower()
                          == "known" else 0,
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "updated_at": now,
        }
        if row is None:
            fields["cve"] = cve
            fields["first_seen"] = now
            cols = ",".join(fields)
            conn.execute(f"INSERT INTO advisories ({cols}) VALUES "
                         f"({','.join('?' for _ in fields)})", list(fields.values()))
            added += 1
        else:
            # never downgrade OSS classification a later OSV pass established
            sets = ",".join(f"{k}=?" for k in fields)
            conn.execute(f"UPDATE advisories SET {sets} WHERE cve=? "
                         f"AND (category != 'oss' OR ?='oss')",
                         list(fields.values()) + [cve, fields["category"]])
            updated += 1
    conn.commit()
    return {"source": "kev", "total": len(vulns), "added": added, "updated": updated}


# --------------------------------------------------------------------------
# EPSS — exploit probability
# --------------------------------------------------------------------------

def enrich_epss(store, cves: list[str], chunk: int = 100) -> int:
    conn = store.conn
    n = 0
    for i in range(0, len(cves), chunk):
        batch = [c for c in cves[i:i + chunk] if c]
        if not batch:
            continue
        try:
            data = _get_json(f"{EPSS_URL}?cve={','.join(batch)}", timeout=45)
        except FeedError:
            continue
        for d in data.get("data") or []:
            cve = d.get("cve")
            try:
                epss = float(d.get("epss"))
                pct = float(d.get("percentile"))
            except (TypeError, ValueError):
                continue
            conn.execute("UPDATE advisories SET epss=?, epss_pct=? WHERE cve=?",
                         (epss, pct, cve))
            n += 1
        time.sleep(0.3)  # be polite to the API
    conn.commit()
    return n


# --------------------------------------------------------------------------
# OSV — is it OSS, and what's the fix?
# --------------------------------------------------------------------------

def _parse_osv(v: dict) -> dict:
    """Pull ecosystem/package/fixed-version/repo/fix-commit out of an OSV record."""
    ecosystem = package = fixed_ver = repo = fix_commit = ""
    for aff in v.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") and not ecosystem:
            ecosystem = pkg["ecosystem"]
            package = pkg.get("name", "")
        for rng in aff.get("ranges") or []:
            rtype = rng.get("type")
            if rtype == "GIT" and rng.get("repo"):
                repo = repo or rng["repo"]
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    if rtype == "GIT":
                        fix_commit = ev["fixed"]
                    else:
                        fixed_ver = ev["fixed"]
    # a repo link from references, if the ranges didn't carry one
    if not repo:
        for ref in v.get("references") or []:
            u = ref.get("url", "")
            if "github.com/" in u and u.count("/") >= 4:
                parts = u.split("github.com/", 1)[1].split("/")
                repo = f"https://github.com/{parts[0]}/{parts[1].split('#')[0]}"
                break
    return {"ecosystem": ecosystem, "package": package,
            "fixed_version": fixed_ver, "repo": repo, "fix_commit": fix_commit}


def enrich_osv(store, cve: str) -> bool:
    """
    Return True if the CVE is an OSS advisory we could act on.

    Actionable means we can locate the source: either an ecosystem+package (so a
    known fixed release exists) or a repo + fix commit (a precise backport
    target — the ideal case). The CVE-primary OSV record often carries only the
    GIT range, with ecosystem/version living in the aliased GHSA record, so we
    follow that alias when needed.
    """
    try:
        v = _get_json(f"{OSV_VULN_URL}{cve}", timeout=30)
    except FeedError:
        # 404 = not in OSV = no open-source record. That is itself a checked
        # result ("no source"), so record that we looked — don't leave it
        # showing as "unchecked" forever.
        store.conn.execute(
            "UPDATE advisories SET osv_checked=1, updated_at=? WHERE cve=?",
            (time.time(), cve))
        store.conn.commit()
        return False

    info = _parse_osv(v)

    # Follow a GHSA alias to fill in ecosystem/package/version if missing.
    if not info["ecosystem"]:
        for alias in v.get("aliases") or []:
            if alias.startswith("GHSA-"):
                try:
                    g = _parse_osv(_get_json(f"{OSV_VULN_URL}{alias}", timeout=30))
                except FeedError:
                    continue
                info["ecosystem"] = info["ecosystem"] or g["ecosystem"]
                info["package"] = info["package"] or g["package"]
                info["fixed_version"] = info["fixed_version"] or g["fixed_version"]
                info["repo"] = info["repo"] or g["repo"]
                info["fix_commit"] = info["fix_commit"] or g["fix_commit"]
                break

    has_source = bool(info["ecosystem"] or (info["repo"] and info["fix_commit"]))
    # Prefer a released version for display; fall back to the fix commit.
    fixed = info["fixed_version"] or info["fix_commit"]

    # A "fixed version" is not a code fix if the advisory is a malicious publish.
    # Check OSV's own text plus whatever KEV gave us.
    conn = store.conn
    stored = conn.execute("SELECT title, description FROM advisories WHERE cve=?",
                          (cve,)).fetchone()
    supply_chain = is_supply_chain(
        v.get("summary", ""), v.get("details", "")[:2000],
        stored["title"] if stored else "", stored["description"] if stored else "")

    if supply_chain:
        conn.execute(
            "UPDATE advisories SET ecosystem=?, package=?, fixed_version=?, "
            "repo_url=COALESCE(NULLIF(?,''), repo_url), category='supply-chain', "
            "actionable=0, osv_checked=1, updated_at=? WHERE cve=?",
            (info["ecosystem"], info["package"], fixed, info["repo"],
             time.time(), cve))
        conn.commit()
        return False

    conn.execute(
        "UPDATE advisories SET ecosystem=?, package=?, fixed_version=?, "
        "repo_url=COALESCE(NULLIF(?,''), repo_url), category=?, actionable=?, "
        "osv_checked=1, updated_at=? WHERE cve=?",
        (info["ecosystem"], info["package"], fixed, info["repo"],
         "oss" if has_source else "app", 1 if has_source else 0,
         time.time(), cve))
    conn.commit()
    return has_source


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------

def ingest(store, osv_limit: int = 200, log=print) -> dict:
    """
    One full intake pass:
      1. pull the whole KEV catalogue (the exploited set)
      2. EPSS-rank everything we now have
      3. OSV-enrich the most-recent N (bounded — OSV is one request per CVE)
    """
    t0 = time.time()
    kev = poll_kev(store)
    log(f"KEV: {kev['total']} exploited, +{kev['added']} new, {kev['updated']} updated")

    conn = store.conn
    all_cves = [r[0] for r in conn.execute("SELECT cve FROM advisories")]
    epss_n = enrich_epss(store, all_cves)
    log(f"EPSS: scored {epss_n}")

    # Enrich the newest advisories first — those are the ones a user is watching.
    recent = [r[0] for r in conn.execute(
        "SELECT cve FROM advisories ORDER BY COALESCE(date_added,'') DESC, "
        "first_seen DESC LIMIT ?", (osv_limit,))]
    act = 0
    for i, cve in enumerate(recent, 1):
        if enrich_osv(store, cve):
            act += 1
        if i % 50 == 0:
            log(f"OSV: {i}/{len(recent)} checked, {act} actionable so far")
        time.sleep(0.15)
    log(f"OSV: {len(recent)} checked, {act} actionable (OSS + fix)")

    conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES "
                 "('last_ingest', ?)", (str(int(time.time())),))
    conn.commit()
    dur = round(time.time() - t0, 1)
    log(f"ingest done in {dur}s")
    return {"kev": kev, "epss": epss_n, "osv_checked": len(recent),
            "actionable": act, "duration_s": dur}


def query(store, *, exploited=None, actionable=None, category=None,
          min_epss=None, min_cvss=None, ransomware=None, search=None,
          new_since=None, order="epss", limit=200, offset=0,
          feed_class=None) -> list[dict]:
    where, params = [], []
    if exploited is not None:
        where.append("exploited=?"); params.append(1 if exploited else 0)
    if actionable is not None:
        where.append("actionable=?"); params.append(1 if actionable else 0)
    if feed_class is not None:
        where.append("feed_class=?"); params.append(feed_class)
    if category:
        where.append("category=?"); params.append(category)
    if min_epss is not None:
        where.append("epss>=?"); params.append(min_epss)
    if min_cvss is not None:
        where.append("cvss>=?"); params.append(min_cvss)
    if ransomware:
        where.append("ransomware=1")
    if new_since is not None:
        where.append("first_seen>=?"); params.append(new_since)
    if search:
        where.append("(cve LIKE ? OR title LIKE ? OR product LIKE ? OR package LIKE ?)")
        params += [f"%{search}%"] * 4
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    order_sql = {"epss": "epss DESC", "date": "date_added DESC",
                 "cvss": "cvss DESC", "seen": "first_seen DESC",
                 "year": "CAST(substr(cve,5,4) AS INTEGER) DESC, epss DESC"}.get(
                     order, "epss DESC")
    rows = store.conn.execute(
        f"SELECT * FROM advisories {clause} ORDER BY {order_sql} NULLS LAST "
        f"LIMIT ? OFFSET ?",
        params + [limit, offset]).fetchall()
    return [dict(r) for r in rows]


def facets(store) -> dict:
    conn = store.conn
    total = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
    by_cat = dict(conn.execute(
        "SELECT category, COUNT(*) FROM advisories GROUP BY category").fetchall())
    exploited = conn.execute("SELECT COUNT(*) FROM advisories WHERE exploited=1").fetchone()[0]
    actionable = conn.execute("SELECT COUNT(*) FROM advisories WHERE actionable=1").fetchone()[0]
    ransomware = conn.execute("SELECT COUNT(*) FROM advisories WHERE ransomware=1").fetchone()[0]
    last = conn.execute("SELECT value FROM meta WHERE key='last_ingest'").fetchone()
    return {"total": total, "by_category": by_cat, "exploited": exploited,
            "actionable": actionable, "ransomware": ransomware,
            "last_ingest": int(last[0]) if last else None}
