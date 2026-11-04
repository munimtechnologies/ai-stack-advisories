# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
"""Census: published releases that fall between an advisory's affected range and its patched version.

For every published GitHub repository security advisory of the 12 self-hosted AI projects that
ai-stack-advisories covers, take the advisories with ONE affected range for the project's own package
and ONE patched version. When the range stops below the patched version ("<= 0.25.1", patched 0.32.0),
list the project's published releases in between (PyPI, npm, or git tags), then record:
  - whether OSV.dev's record for the same GHSA marks each of those releases affected;
  - whether the ai-stack-advisories feed flags each of them.
v2 (2026-11-03): v1 ran out of the shared 60/hour unauthenticated GitHub API budget after 3 of 12 projects.
  - advisories already fetched by v1 can be seeded from a file (argv[3]); only the missing repos are fetched;
  - git tags come from `git ls-remote --tags` (no API budget) instead of the paginated tags API;
  - an advisory with a blank or unknown package uses the project's own registry package (DEFAULT_PKG);
  - on a GitHub rate-limit answer the census waits for X-RateLimit-Reset (at most twice) and goes on.
Standard library only. Usage: python gap_census.py <ai-stack-advisories clone> <out dir> [seed json]
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

LEADING_ZERO_RE = re.compile(r"(?:^|\.)0\d")
UA = "ai-stack-advisories-gap-census (MV2 of Munim, Inc.)"

GH_CALLS = {"n": 0, "remaining": None, "waits": 0, "waited_s": 0}
MAX_WAITS = 2

# The project's own release line when an advisory's package is blank or unknown to its registry.
DEFAULT_PKG = {
    "openwebui": ("pip", "open-webui"),
    "vllm": ("pip", "vllm"),
    "langflow": ("pip", "langflow"),
    "litellm": ("pip", "litellm"),
    "flowise": ("npm", "flowise"),
    "n8n": ("npm", "n8n"),
    "mcpinspector": ("npm", "@modelcontextprotocol/inspector"),
}


def strip_v(text):
    text = (text or "").strip()
    return text[1:] if text[:1] in ("v", "V") and text[1:2].isdigit() else text


PRE_WORDS = {"a", "b", "c", "rc", "dev", "alpha", "beta", "pre", "preview", "next", "canary", "nightly",
             "exp", "test", "snapshot"}


def is_prerelease(version):
    rest = re.sub(r"^\d+(\.\d+)*", "", strip_v(version))
    return any(word.lower() in PRE_WORDS for word in re.findall(r"[A-Za-z]+", rest))


def single_patched(text):
    parts = [p.strip() for p in (text or "").split(",") if p.strip()]
    if len(parts) != 1:
        return None
    m = re.fullmatch(r"(?:(?:>=|=>)\s*)?(v?\d[0-9A-Za-z.+\-]*)", parts[0])
    if not m:
        return None
    ver = strip_v(m.group(1))
    return None if LEADING_ZERO_RE.search(ver) else ver


def gap_bounds(cf, range_text, patched):
    """Return (hi, hi_inclusive) when the single range stops below `patched`, else None."""
    if not range_text or range_text.count("<") > 1:
        return None  # several release lines in one string: not a single range
    if any(LEADING_ZERO_RE.search(strip_v(t)) for t in re.findall(r"[0-9vV][0-9A-Za-z.+\-]*", range_text)):
        return None  # "< 030.0": a typo, reported elsewhere
    parsed = cf.parse_range(range_text)
    if parsed is None:
        return None
    lo, hi, incl = parsed
    if hi is None:
        return None
    hi = strip_v(hi)
    if cf.version_key(patched) <= cf.version_key(hi):
        return None
    if lo is not None and cf.version_key(patched) <= cf.version_key(strip_v(lo)):
        return None
    return hi, incl


def in_gap(cf, version, hi, incl, patched):
    k = cf.version_key(strip_v(version))
    above = k > cf.version_key(hi) if incl else k >= cf.version_key(hi)
    return above and k < cf.version_key(patched)


def osv_affects(cf, record, names, version):
    """True/False whether OSV's record marks `version` affected for one of `names`; None if no package matches."""
    matched = False
    key = cf.version_key(strip_v(version))
    for aff in record.get("affected") or []:
        name = ((aff.get("package") or {}).get("name") or "").lower()
        if name not in names:
            continue
        matched = True
        if strip_v(version) in [strip_v(v) for v in aff.get("versions") or []]:
            return True
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            start = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    start = ev["introduced"]
                elif start is not None and ("fixed" in ev or "last_affected" in ev):
                    lo_ok = start == "0" or cf.version_key(strip_v(start)) <= key
                    if "fixed" in ev:
                        hi_ok = key < cf.version_key(strip_v(ev["fixed"]))
                    else:
                        hi_ok = key <= cf.version_key(strip_v(ev["last_affected"]))
                    if lo_ok and hi_ok:
                        return True
                    start = None
            if start is not None and (start == "0" or cf.version_key(strip_v(start)) <= key):
                return True
    return False if matched else None


def feed_flags(cf, items, version):
    return cf.first_gap(items, version, version, True) is None


def rate_limit_wait(headers, now=None):
    """Seconds to wait before the GitHub budget resets (None if the answer is not a rate limit)."""
    if headers is None or str(headers.get("X-RateLimit-Remaining", "")) != "0":
        return None
    try:
        reset = int(headers.get("X-RateLimit-Reset"))
    except (TypeError, ValueError):
        return 900
    return max(5, min(3700, reset - int(now if now is not None else time.time()) + 5))


def http_json(url, headers=None, github=False):
    req = urllib.request.Request(url, headers=dict({"User-Agent": UA}, **(headers or {})))
    attempt = 0
    while attempt < 3:
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                if github:
                    GH_CALLS["n"] += 1
                    GH_CALLS["remaining"] = resp.headers.get("X-RateLimit-Remaining")
                return json.load(resp), resp.headers
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None, None
            wait = rate_limit_wait(err.headers) if github and err.code in (403, 429) else None
            if wait is not None and GH_CALLS["waits"] < MAX_WAITS:
                GH_CALLS["waits"] += 1
                GH_CALLS["waited_s"] += wait
                print("RATE LIMIT: waiting %ds for the GitHub budget (%s)" % (wait, url), flush=True)
                time.sleep(wait)
                continue  # does not use up an attempt
            if attempt == 2 or err.code not in (429, 500, 502, 503, 504):
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
        attempt += 1
        time.sleep(5 * attempt)
    return None, None


def github_pages(url):
    out = []
    while url:
        data, headers = http_json(url, {"Accept": "application/vnd.github+json",
                                        "X-GitHub-Api-Version": "2022-11-28"}, github=True)
        if data is None:
            break
        out.extend(data)
        m = re.search(r'<([^>]+)>;\s*rel="next"', (headers or {}).get("Link") or "")
        url = m.group(1) if m else None
    return out


def parse_ls_remote(text):
    """Version-like tag names from `git ls-remote --tags` output (peeled ^{} lines folded)."""
    names = set()
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not parts[1].startswith("refs/tags/"):
            continue
        tag = parts[1][len("refs/tags/"):]
        if tag.endswith("^{}"):
            tag = tag[:-3]
        if re.match(r"^v?\d", tag):
            names.add(strip_v(tag))
    return sorted(names)


def git_tags(repo):
    res = subprocess.run(["git", "ls-remote", "--tags", "https://github.com/%s" % repo],
                         capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        raise RuntimeError("git ls-remote %s: %s" % (repo, res.stderr.strip()[:200]))
    return parse_ls_remote(res.stdout)


def registry_versions(ecosystem, name):
    if ecosystem == "pip" and name:
        data, _ = http_json("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name))
        if data:
            versions = []
            for ver, files in (data.get("releases") or {}).items():
                if files and all(f.get("yanked") for f in files):
                    continue
                if files:
                    versions.append(ver)
            return "pypi:" + name, versions
    elif ecosystem == "npm" and name:
        data, _ = http_json("https://registry.npmjs.org/" + name.replace("/", "%2F"),
                            {"Accept": "application/vnd.npm.install-v1+json"})
        if data:
            return "npm:" + name, [v for v, meta in (data.get("versions") or {}).items()
                                   if not (meta or {}).get("deprecated")]
    return None, []


def releases_for(ecosystem, name, repo, cache, app=None):
    key = (ecosystem, name, repo)
    if key in cache:
        return cache[key]
    source, versions = registry_versions(ecosystem, name)
    if source is None and app in DEFAULT_PKG:
        source, versions = registry_versions(*DEFAULT_PKG[app])
        if source:
            source += " (project default; advisory package %r)" % name
    if source is None and repo:
        source, versions = "git-tags:" + repo, git_tags(repo)
    cache[key] = (source, sorted(set(versions)))
    return cache[key]


def census(cf, feed, fetch_advisories, fetch_osv, fetch_releases):
    rows, per_app = [], {}
    for app, repo in cf.PROJECTS.items():
        names = cf.PACKAGES.get(app, set())
        items = (feed.get("products", {}).get(app) or {}).get("items", [])
        stats = per_app.setdefault(app, {"advisories": 0, "single_range_single_patch": 0, "gap": 0,
                                         "gap_with_stable_release": 0, "stable_releases_in_gaps": 0,
                                         "osv_marks_all": 0, "osv_marks_some": 0, "osv_marks_none": 0,
                                         "osv_missing": 0, "osv_no_matching_package": 0,
                                         "feed_flags_all": 0, "release_source": None})
        for adv in fetch_advisories(repo):
            stats["advisories"] += 1
            vulns = adv.get("vulnerabilities") or []
            own = [v for v in vulns if ((v.get("package") or {}).get("name") or "").lower() in names]
            chosen = own or vulns
            if len(chosen) != 1:
                continue
            vuln = chosen[0]
            patched = single_patched(vuln.get("patched_versions"))
            rng = (vuln.get("vulnerable_version_range") or "").strip()
            if patched is None or not rng:
                continue
            stats["single_range_single_patch"] += 1
            bounds = gap_bounds(cf, rng, patched)
            if bounds is None:
                continue
            hi, incl = bounds
            stats["gap"] += 1
            pkg = vuln.get("package") or {}
            source, versions = fetch_releases(pkg.get("ecosystem") or "", (pkg.get("name") or "").strip(), repo, app)
            stats["release_source"] = stats["release_source"] or source
            between = [v for v in versions if in_gap(cf, v, hi, incl, patched)]
            stable = sorted([v for v in between if not is_prerelease(v)], key=lambda v: cf.version_key(v))
            ghsa = adv.get("ghsa_id")
            record = fetch_osv(ghsa) if stable else None
            osv_names = names | {(pkg.get("name") or "").lower()}
            if not stable:
                osv_state, osv_marked = "n/a", None
            elif record is None:
                osv_state, osv_marked = "missing", None
            else:
                marks = [osv_affects(cf, record, osv_names, v) for v in stable]
                osv_marked = sum(1 for m in marks if m)
                if any(m is None for m in marks):
                    osv_state = "no matching package"
                else:
                    osv_state = "all" if osv_marked == len(stable) else ("none" if osv_marked == 0 else "some")
            flagged = [feed_flags(cf, items, v) for v in stable]
            if stable:
                stats["gap_with_stable_release"] += 1
                stats["stable_releases_in_gaps"] += len(stable)
                if osv_state == "missing":
                    stats["osv_missing"] += 1
                elif osv_state == "no matching package":
                    stats["osv_no_matching_package"] += 1
                elif osv_state in ("all", "some", "none"):
                    stats["osv_marks_" + osv_state] += 1
                if all(flagged):
                    stats["feed_flags_all"] += 1
            rows.append({
                "app": app, "ghsa": ghsa, "cve": adv.get("cve_id"),
                "severity": (adv.get("severity") or "").upper() or None,
                "published": (adv.get("published_at") or "")[:10],
                "package": pkg.get("name"), "ecosystem": pkg.get("ecosystem"),
                "range": rng, "patched": vuln.get("patched_versions"),
                "release_source": source,
                "stable_releases_in_gap": stable,
                "prereleases_in_gap": len(between) - len(stable),
                "osv": osv_state, "osv_marks": osv_marked,
                "osv_reviewed": None if record is None else (record.get("database_specific") or {}).get("github_reviewed"),
                "feed_flags_all": all(flagged) if stable else None,
                "url": adv.get("html_url"),
            })
    return rows, per_app


def main(argv):
    clone, out = argv[1], argv[2]
    seed = {}
    if len(argv) > 3 and argv[3] and os.path.exists(argv[3]):
        with open(argv[3], encoding="utf-8") as fh:
            seed = {k: v for k, v in json.load(fh).items() if v}
    sys.path.insert(0, clone)
    import check_freshness as cf  # noqa: E402

    with open(os.path.join(clone, "advisories.json"), encoding="utf-8") as fh:
        feed = json.load(fh)
    cache, errors, raw, seeded = {}, [], {}, []

    def fetch_adv(repo):
        if repo in seed:
            seeded.append("%s (%d)" % (repo, len(seed[repo])))
            raw[repo] = seed[repo]
            return raw[repo]
        try:
            raw[repo] = github_pages(cf.API.format(repo))
            return raw[repo]
        except Exception as exc:  # recorded, census marked partial
            errors.append("advisories %s: %s" % (repo, exc))
            return []

    def fetch_osv(ghsa):
        try:
            data, _ = http_json("https://api.osv.dev/v1/vulns/" + ghsa)
            return data
        except Exception as exc:
            errors.append("osv %s: %s" % (ghsa, exc))
            return None

    def fetch_rel(eco, name, repo, app=None):
        try:
            return releases_for(eco, name, repo, cache, app)
        except Exception as exc:
            errors.append("releases %s %s %s: %s" % (eco, name, repo, exc))
            return ("error", [])

    rows, per_app = census(cf, feed, fetch_adv, fetch_osv, fetch_rel)
    report = {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "errors": errors,
              "seeded_from_v1": seeded, "github_calls": GH_CALLS["n"], "github_remaining": GH_CALLS["remaining"],
              "github_waits": GH_CALLS["waits"], "github_waited_s": GH_CALLS["waited_s"],
              "per_app": per_app, "rows": rows}
    with open(os.path.join(out, "gap_census.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    with open(os.path.join(out, "repo_advisories.json"), "w", encoding="utf-8") as fh:
        json.dump(raw, fh)
    lines = ["CHECKED %s github_calls=%s remaining=%s waits=%s waited_s=%s" % (
        report["checked_at"], GH_CALLS["n"], GH_CALLS["remaining"], GH_CALLS["waits"], GH_CALLS["waited_s"])]
    lines += ["SEEDED " + s for s in seeded]
    lines += ["ERROR " + e for e in errors]
    total = {}
    for app, s in per_app.items():
        lines.append("PER_APP %-12s %s" % (app, json.dumps(s, sort_keys=True)))
        for k, v in s.items():
            if isinstance(v, int):
                total[k] = total.get(k, 0) + v
    lines.append("TOTAL %s" % json.dumps(total, sort_keys=True))
    for r in sorted(rows, key=lambda r: (r["app"], -len(r["stable_releases_in_gap"]))):
        if r["stable_releases_in_gap"]:
            rel = r["stable_releases_in_gap"]
            lines.append("GAP %-12s %s %s %s range=%r patched=%r n=%d first=%s last=%s osv=%s marks=%s feed_all=%s src=%s" % (
                r["app"], r["ghsa"], r["cve"] or "-", r["severity"], r["range"], r["patched"], len(rel),
                rel[0], rel[-1], r["osv"], r["osv_marks"], r["feed_flags_all"], r["release_source"]))
    with open(os.path.join(out, "gap_census.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(l for l in lines if not l.startswith("GAP ")))
    print("GAP rows with >=1 stable release: %d" % sum(1 for r in rows if r["stable_releases_in_gap"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
