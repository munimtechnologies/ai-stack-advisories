#!/usr/bin/env python3
# MV2 of Munim, Inc. - work made with AI. Apache-2.0.
#
# Reproducible census: how many published GitHub security advisories (GHSAs) for
# popular self-hosted AI apps carry no CVE id, and how that gap breaks down by
# repo and by severity. Reads the raw JSON produced by the `advisory-verify`
# compute job (each advisory object comes straight from that repo's own
# GET /repos/{owner}/{repo}/security-advisories?state=published endpoint).
#
# Usage:  python -I cve_assignment_gap.py advisories.json [out.json]
# Emits a summary to stdout and, if out.json is given, writes the machine-readable
# counts there. No network, no third-party deps (standard library only).

import json
import sys
from collections import defaultdict


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def census(data):
    total = 0
    no_cve = 0
    by_repo = {}
    by_sev = defaultdict(lambda: {"total": 0, "no_cve": 0})
    for repo in data.get("repos", []):
        name = repo["repo"]
        advs = repo.get("advisories", []) or []
        r_total = 0
        r_no_cve = 0
        for a in advs:
            r_total += 1
            total += 1
            sev = (a.get("severity") or "unknown").lower()
            by_sev[sev]["total"] += 1
            if a.get("cve_id") in (None, "", "null"):
                r_no_cve += 1
                no_cve += 1
                by_sev[sev]["no_cve"] += 1
        by_repo[name] = {"total": r_total, "no_cve": r_no_cve}
    return {
        "fetched_at": data.get("fetched_at"),
        "total_advisories": total,
        "no_cve": no_cve,
        "with_cve": total - no_cve,
        "no_cve_pct": round(100.0 * no_cve / total, 2) if total else 0.0,
        "by_repo": by_repo,
        "by_severity": {
            s: {
                "total": v["total"],
                "no_cve": v["no_cve"],
                "no_cve_pct": round(100.0 * v["no_cve"] / v["total"], 2) if v["total"] else 0.0,
            }
            for s, v in sorted(by_sev.items())
        },
    }


def main():
    if len(sys.argv) < 2:
        print("usage: python -I cve_assignment_gap.py advisories.json [out.json]", file=sys.stderr)
        return 2
    result = census(load(sys.argv[1]))
    print("snapshot:", result["fetched_at"])
    print(f"total advisories: {result['total_advisories']}")
    print(f"no CVE id: {result['no_cve']} ({result['no_cve_pct']}%)")
    print(f"with CVE id: {result['with_cve']}")
    print("\nby repo (no_cve / total):")
    for name, v in sorted(result["by_repo"].items(), key=lambda kv: -kv[1]["total"]):
        pct = round(100.0 * v["no_cve"] / v["total"], 1) if v["total"] else 0.0
        print(f"  {name:28s} {v['no_cve']:4d} / {v['total']:4d}  ({pct}%)")
    print("\nby severity (no_cve / total):")
    for sev, v in result["by_severity"].items():
        print(f"  {sev:10s} {v['no_cve']:4d} / {v['total']:4d}  ({v['no_cve_pct']}%)")
    if len(sys.argv) >= 3:
        with open(sys.argv[2], "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"\nwrote {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
