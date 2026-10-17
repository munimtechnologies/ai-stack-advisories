# SPDX-License-Identifier: Apache-2.0
# Part of ai-stack-advisories by MV2, Munim, Inc. Made with AI.
"""Pure, stdlib-only logic for the OSV coverage census and first-seen ledger.

Network I/O lives in census.py; everything here is deterministic and unit-tested
offline so the publish lane's test_first can run it without network access.
"""
from __future__ import annotations

from datetime import datetime, timezone


def parse_iso(ts: str) -> datetime:
    """Parse a GitHub/OSV RFC3339 timestamp (trailing 'Z' allowed)."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def days_between(earlier_iso: str, later_iso: str) -> int:
    """Whole days between two ISO timestamps (later - earlier), floored at 0."""
    delta = parse_iso(later_iso) - parse_iso(earlier_iso)
    return max(0, delta.days)


def parse_advisory(adv: dict) -> dict:
    """Extract the fields we track from a GitHub repo-level advisory object."""
    vulns = adv.get("vulnerabilities") or []
    first_patched = None
    for v in vulns:
        fpv = (v or {}).get("first_patched_version")
        if isinstance(fpv, dict) and fpv.get("identifier"):
            first_patched = fpv["identifier"]
            break
    return {
        "ghsa_id": adv.get("ghsa_id"),
        "cve_id": adv.get("cve_id"),
        "severity": (adv.get("severity") or "unknown").lower(),
        "published_at": adv.get("published_at"),
        "withdrawn_at": adv.get("withdrawn_at"),
        "first_patched_version": first_patched,
        "has_fix": first_patched is not None,
    }


def summarize(records: list[dict], now_iso: str) -> dict:
    """Aggregate per-advisory records into a dated coverage snapshot.

    Each record must have: ghsa_id, severity, published_at, osv_present (bool).
    """
    active = [r for r in records if not r.get("withdrawn_at")]
    total = len(active)
    in_osv = [r for r in active if r.get("osv_present")]
    absent = [r for r in active if not r.get("osv_present")]

    def sev_counts(rows: list[dict]) -> dict:
        out: dict[str, int] = {}
        for r in rows:
            sev = r.get("severity", "unknown")
            out[sev] = out.get(sev, 0) + 1
        return dict(sorted(out.items()))

    oldest_absent = None
    for r in absent:
        pub = r.get("published_at")
        if not pub:
            continue
        age = days_between(pub, now_iso)
        if oldest_absent is None or age > oldest_absent["age_days"]:
            oldest_absent = {"ghsa_id": r["ghsa_id"], "age_days": age}

    pct = round(100.0 * len(in_osv) / total, 1) if total else 0.0
    return {
        "as_of": now_iso,
        "total_active_advisories": total,
        "in_osv": len(in_osv),
        "absent_from_osv": len(absent),
        "osv_coverage_pct": pct,
        "severity_all": sev_counts(active),
        "severity_absent": sev_counts(absent),
        "oldest_absent": oldest_absent,
        "absent_list": sorted(
            (
                {
                    "ghsa_id": r["ghsa_id"],
                    "severity": r.get("severity", "unknown"),
                    "published_at": r.get("published_at"),
                    "age_days": days_between(r["published_at"], now_iso)
                    if r.get("published_at")
                    else None,
                }
                for r in absent
            ),
            key=lambda x: (x["age_days"] is None, -(x["age_days"] or 0)),
        ),
    }


def merge_ledger(ledger: dict, records: list[dict], now_iso: str) -> dict:
    """Update the persistent first-seen ledger with this run's observations.

    The ledger is the novel part: by recording, per GHSA, when GitHub published it
    and the first run at which OSV began returning a record, repeated runs build the
    first real OSV *ingestion-latency* distribution for self-hosted-AI advisories.

    Returns a new dict; does not mutate the input.
    """
    out = {k: dict(v) for k, v in ledger.items()}
    for r in records:
        ghsa = r.get("ghsa_id")
        if not ghsa:
            continue
        present = bool(r.get("osv_present"))
        if ghsa not in out:
            out[ghsa] = {
                "ghsa_id": ghsa,
                "severity": r.get("severity", "unknown"),
                "published_at": r.get("published_at"),
                "first_checked": now_iso,
                "osv_present": present,
                "osv_first_seen": now_iso if present else None,
            }
        else:
            entry = out[ghsa]
            # Record the moment OSV ingestion first flips from absent to present.
            if present and not entry.get("osv_present"):
                entry["osv_first_seen"] = now_iso
            entry["osv_present"] = present
            entry.setdefault("published_at", r.get("published_at"))
    return out


def ledger_latency_stats(ledger: dict) -> dict:
    """Summarize observed ingestion latencies from the ledger.

    Latency is only defined for advisories whose OSV appearance we actually
    witnessed (osv_first_seen set and after first_checked). Honest limit: records
    already in OSV at first sight give a right-censored lower bound, not a latency.
    """
    observed = []
    for entry in ledger.values():
        fs = entry.get("osv_first_seen")
        fc = entry.get("first_checked")
        pub = entry.get("published_at")
        if fs and fc and fs > fc and pub:
            observed.append(days_between(pub, fs))
    observed.sort()
    n = len(observed)
    median = None
    if n:
        median = observed[n // 2] if n % 2 else (observed[n // 2 - 1] + observed[n // 2]) / 2
    return {
        "witnessed_ingestions": n,
        "median_latency_days": median,
        "min_latency_days": observed[0] if observed else None,
        "max_latency_days": observed[-1] if observed else None,
        "still_absent": sum(1 for e in ledger.values() if not e.get("osv_present")),
        "total_tracked": len(ledger),
    }
