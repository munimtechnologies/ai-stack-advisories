"""Find published GitHub security advisories that advisories.json doesn't list yet.

For each covered project this pages through
GET /repos/{owner}/{repo}/security-advisories?state=published and reports every
advisory whose GHSA and CVE IDs both appear nowhere in advisories.json (or in
pending-advisories.json, when it exists). For each one it also says whether the
feed's existing entries already flag the advisory's whole affected range, so a
missing ID can be told apart from versions a scan would not flag at all.

Range check notes:
- Coverage is checked against the union of an app's entries; entries with `only`
  are ignored, so the check errs toward "not flagged".
- When an advisory lists several ranges for the same package that all lack a
  lower bound (the way n8n and LiteLLM publish per release line), every range but
  the lowest is read as starting at its own release line (major.minor.0).
- A range written as several release lines in one string ("< 1.123.22, >= 2.0.0
  < 2.9.3", as n8n does) is read as a union: a lower bound that follows an upper
  bound starts a new range. Comparators separated only by a space are read too.
- Free-text ranges ("all versions carrying the ... fix") are reported as
  "range not parsed" for a person to check.
- A single range that ends below the one version patched_versions names
  ("<= 0.25.1" with patched "0.32.0", or a bare "0.26.0") counts as affected up
  to that version, because the releases in between don't have the fix; OSV.dev
  reads such advisories the same way. "=>" in patched_versions is read as ">=".
- A version with a leading zero ("< 030.0") is reported as "range not parsed":
  it is almost always a typo, and read literally it would cover every release.

Usage:
  python check_freshness.py [--feed advisories.json] [--pending pending-advisories.json]
                            [--app vllm] [--json]
Set GITHUB_TOKEN to raise GitHub's rate limit (60 requests an hour without one).
Exit code: 0 when nothing is missing, 1 when something is. Standard library only.
By MV2 of Munim, Inc.
"""

import argparse
import json
import os
import re
import sys
import urllib.request

PROJECTS = {
    "ollama": "ollama/ollama",
    "openwebui": "open-webui/open-webui",
    "vllm": "vllm-project/vllm",
    "langflow": "langflow-ai/langflow",
    "flowise": "FlowiseAI/Flowise",
    "litellm": "BerriAI/litellm",
    "n8n": "n8n-io/n8n",
    "dify": "langgenius/dify",
    "ragflow": "infiniflow/ragflow",
    "anythingllm": "Mintplex-Labs/anything-llm",
    "comfyui": "Comfy-Org/ComfyUI",
    "mcpinspector": "modelcontextprotocol/inspector",
}

# Package names that carry the app's own version numbers. Ranges for other
# packages in the same advisory (langflow-base, lfx, ...) use other schemes.
PACKAGES = {
    "ollama": {"ollama", "github.com/ollama/ollama"},
    "openwebui": {"open-webui"},
    "vllm": {"vllm"},
    "langflow": {"langflow"},
    "flowise": {"flowise"},
    "litellm": {"litellm"},
    "n8n": {"n8n"},
    "dify": {"dify", "langgenius/dify"},
    "ragflow": {"ragflow", "infiniflow/ragflow"},
    "anythingllm": {"anything-llm", "mintplex-labs/anything-llm"},
    "comfyui": {"comfyui"},
    "mcpinspector": {"@modelcontextprotocol/inspector"},
}

ID_RE = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}|CVE-\d{4}-\d{4,}", re.IGNORECASE)
API = "https://api.github.com/repos/{}/security-advisories?state=published&per_page=100"

# Version keys: numbers sort above letters, so 1.104.0rc1 < 1.104.0 < 1.104.1.
_END = (0.5, 0, "")
_IGNORED_WORDS = {"v", "stable"}


def version_key(text):
    tokens = [t for t in re.findall(r"\d+|[a-zA-Z]+", text) if t.lower() not in _IGNORED_WORDS]
    release = []
    while tokens and tokens[0].isdigit():
        release.append(int(tokens.pop(0)))
    while release and release[-1] == 0:
        release.pop()
    key = [(1, n, "") for n in release]
    for token in tokens:
        key.append((1, int(token), "") if token.isdigit() else (0, 0, token.lower()))
    key.append(_END)
    return tuple(key)


def _looks_like_version(text):
    if re.fullmatch(r"v?\d[0-9A-Za-z.+\-]*", text) is None:
        return False
    # "030.0" (vLLM's GHSA-2phq-3phc-84px) is a typo, not a version: read literally it covers every release.
    return re.search(r"(?:^v?|\.)0\d", text) is None


def parse_range(text):
    """Return (lo, hi, hi_inclusive) as version strings (None = unbounded), or None."""
    text = (text or "").strip()
    if not text:
        return None
    lo = hi = None
    hi_incl = False
    for part in text.split(","):
        part = part.strip()
        match = re.fullmatch(r"(>=|>|<=|<|=)?\s*(\S+)", part)
        if not match or not _looks_like_version(match.group(2)):
            return None
        op, ver = match.group(1) or "=", match.group(2)
        if op in (">=", ">"):
            lo = ver
        elif op == "<":
            hi, hi_incl = ver, False
        elif op == "<=":
            hi, hi_incl = ver, True
        else:
            lo, hi, hi_incl = ver, ver, True
    return lo, hi, hi_incl


# One comparator and its version, after any spaces or commas. A version can't hold a comparator
# character, so "<1.120.3" splits and a bare ">=" is never read as a version.
_COMPARATOR = re.compile(r"[\s,]*(>=|>|<=|<|=)?\s*([^\s,<>=]+)")


def _comparators(text):
    """Return [(op, version), ...] covering the whole text, or None if anything else is left over."""
    pairs = []
    pos = 0
    while pos < len(text):
        match = _COMPARATOR.match(text, pos)
        if not match:
            return None
        pairs.append((match.group(1) or "=", match.group(2)))
        pos = match.end()
    return pairs


def parse_ranges(text):
    """Return a list of (lo, hi, hi_inclusive) for a range that may hold several release lines, or None.

    n8n writes "< 1.123.22, >= 2.0.0 < 2.9.3, >= 2.10.0 < 2.10.1" for three release lines, and some
    advisories leave out the comma (">= 0.187.0 <1.120.3"). A lower bound that follows an upper bound
    starts a new range; any word that isn't a version makes the whole text unparsed."""
    text = (text or "").strip()
    if not text:
        return None
    pairs = _comparators(text)
    if pairs is None:
        return None
    ranges = []
    lo = hi = None
    hi_incl = False
    for op, ver in pairs:
        if not _looks_like_version(ver):
            return None
        if op in (">=", ">"):
            if hi is not None:
                ranges.append((lo, hi, hi_incl))
                hi, hi_incl = None, False
            elif lo is not None:
                return None
            lo = ver
        elif op in ("<", "<="):
            if hi is not None:
                return None
            hi, hi_incl = ver, op == "<="
        else:
            if lo is not None and hi is None:
                return None
            if hi is not None:
                ranges.append((lo, hi, hi_incl))
            ranges.append((ver, ver, True))
            lo = hi = None
            hi_incl = False
    if lo is not None or hi is not None:
        ranges.append((lo, hi, hi_incl))
    return ranges or None


def _inverted(rng):
    """True for a range whose lower bound is above its upper bound ("< 1.123.8, >= 2.0.0" read as AND)."""
    lo, hi, _ = rng
    return lo is not None and hi is not None and version_key(lo) > version_key(hi)


def _single_patched(vuln):
    """The one version patched_versions names (">= 0.32.0", "=> 0.26.0" or "0.32.0"), else None."""
    parts = [p.strip() for p in (vuln.get("patched_versions") or "").split(",") if p.strip()]
    if len(parts) != 1:
        return None
    m = re.fullmatch(r"(?:(?:>=|=>)\s*)?v?(\S+)", parts[0])
    if not m or not _looks_like_version(m.group(1)):
        return None
    return m.group(1)


def _with_patched(rng, vuln, gap=False):
    """End a range at the one version patched_versions names, when the range stops short of it.

    Many vLLM and n8n advisories give only a lower bound (">=0.1.0") as the range and put the fix in
    patched_versions ("0.10.1.1"). Several patched versions (one per release line) stay open-ended.
    With gap=True (the advisory has a single range), a range whose upper bound is below the patched
    version ("<= 0.25.1" with patched "0.32.0", or a bare "0.26.0") is extended to it: no release
    before the patched one has the fix."""
    if not rng:
        return rng
    patched = _single_patched(vuln)
    if patched is None:
        return rng
    lo, hi, _ = rng
    if lo is not None and version_key(patched) <= version_key(lo):
        return rng
    if hi is None or (gap and version_key(patched) > version_key(hi)):
        return (lo, patched, False)
    return rng


def _line_start(version):
    numbers = re.findall(r"\d+", version)
    if len(numbers) < 2:
        return None
    return "{}.{}.0".format(numbers[0], numbers[1])


def advisory_ranges(advisory, app):
    """Return the affected ranges for the app's own package, or None if any can't be parsed."""
    vulns = advisory.get("vulnerabilities") or []
    names = PACKAGES.get(app, set())
    own = [v for v in vulns if ((v.get("package") or {}).get("name") or "").lower() in names]
    ranges = []
    chosen = own or vulns
    for vuln in chosen:
        text = vuln.get("vulnerable_version_range")
        parsed = parse_range(text)
        found = [parsed] if parsed is not None and not _inverted(parsed) else parse_ranges(text)
        if found is None:
            return None
        single = len(chosen) == 1 and len(found) == 1
        ranges.extend(_with_patched(r, vuln, gap=single) for r in found)
    if not ranges:
        return None
    if len(ranges) > 1 and all(r[0] is None and r[1] is not None for r in ranges):
        ranges.sort(key=lambda r: version_key(r[1]))
        ranges = [ranges[0]] + [(_line_start(hi), hi, incl) for _, hi, incl in ranges[1:]]
    return ranges


def _bound(version, inclusive):
    return (version_key(version), 1 if inclusive else 0)


def first_gap(items, lo, hi, hi_incl):
    """Return None if the entries flag every version in [lo, hi], else the version where flagging stops."""
    entries = []
    for item in items:
        if item.get("only"):
            continue
        start = item.get("introduced")
        if item.get("fixed"):
            end = (item["fixed"], False)
        elif item.get("lastAffected"):
            end = (item["lastAffected"], True)
        else:
            end = None
        entries.append((start, end))

    # frontier: every version below (or up to, when inclusive) this point is flagged.
    frontier = None if lo is None else (lo, False)
    target = None if hi is None else (hi, hi_incl)
    changed = True
    while changed:
        if frontier is not None and target is not None and _bound(*frontier) >= _bound(*target):
            return None
        changed = False
        for start, end in entries:
            if start is not None and (frontier is None or version_key(start) > version_key(frontier[0])):
                continue
            if end is None:
                return None
            if frontier is None or _bound(*end) > _bound(*frontier):
                frontier = end
                changed = True
    if frontier is not None and target is not None and _bound(*frontier) >= _bound(*target):
        return None
    return "the first version" if frontier is None else frontier[0]


def known_ids(*texts):
    ids = set()
    for text in texts:
        ids.update(m.upper() for m in ID_RE.findall(text or ""))
    return ids


def check_app(app, items, advisories, listed):
    """Return one report dict per advisory whose IDs are all missing from `listed`."""
    missing = []
    for adv in advisories:
        ids = [i for i in (adv.get("ghsa_id"), adv.get("cve_id")) if i]
        if any(i.upper() in listed for i in ids):
            continue
        ranges = advisory_ranges(adv, app)
        if ranges is None:
            status, gap = "range not parsed", None
        else:
            gaps = [first_gap(items, lo, hi, incl) for lo, hi, incl in ranges]
            gaps = [g for g in gaps if g is not None]
            gap = gaps[0] if gaps else None
            status = "not flagged" if gaps else "range already flagged"
        missing.append({
            "app": app,
            "ids": ids,
            "severity": (adv.get("severity") or "").upper() or None,
            "published": (adv.get("published_at") or "")[:10],
            "ranges": [v.get("vulnerable_version_range") for v in adv.get("vulnerabilities") or []],
            "status": status,
            "notFlaggedFrom": gap,
            "summary": adv.get("summary"),
            "url": adv.get("html_url"),
        })
    return missing


def fetch_advisories(repo, token=None):
    url = API.format(repo)
    results = []
    while url:
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ai-stack-advisories-check-freshness",
        })
        if token:
            request.add_header("Authorization", "Bearer " + token)
        with urllib.request.urlopen(request, timeout=60) as response:
            results.extend(json.load(response))
            match = re.search(r'<([^>]+)>;\s*rel="next"', response.headers.get("Link") or "")
        url = match.group(1) if match else None
    return results


def run(feed_text, pending_text, fetch, apps=None):
    feed = json.loads(feed_text)
    listed = known_ids(feed_text, pending_text)
    report = []
    for app, repo in PROJECTS.items():
        if apps and app not in apps:
            continue
        items = (feed.get("products", {}).get(app) or {}).get("items", [])
        report.extend(check_app(app, items, fetch(repo), listed))
    return report


def _read(path):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    return ""


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--feed", default=os.path.join(here, "advisories.json"))
    parser.add_argument("--pending", default=os.path.join(here, "pending-advisories.json"))
    parser.add_argument("--app", action="append", choices=sorted(PROJECTS))
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    report = run(_read(args.feed), _read(args.pending),
                 lambda repo: fetch_advisories(repo, token), args.app)
    if args.json:
        print(json.dumps(report, indent=2))
    elif not report:
        print("No published advisories missing.")
    else:
        for row in report:
            where = " from " + row["notFlaggedFrom"] if row["notFlaggedFrom"] else ""
            print("{app:12} {ids} {sev} {pub}  {ranges}  -> {status}{where}".format(
                app=row["app"], ids="/".join(row["ids"]), sev=row["severity"] or "-",
                pub=row["published"], ranges="; ".join(r or "?" for r in row["ranges"]),
                status=row["status"], where=where))
        print("{} missing.".format(len(report)))
    return 1 if report else 0


if __name__ == "__main__":
    sys.exit(main())
