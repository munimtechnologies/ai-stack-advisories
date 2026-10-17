# SPDX-License-Identifier: Apache-2.0
# Part of ai-stack-advisories by MV2, Munim, Inc. Made with AI.
"""OSV coverage census for self-hosted-AI projects.

For a fixed set of self-hosted-AI repositories this script:
  1. reads each repo's published security advisories from GitHub's public REST API,
  2. checks whether each GHSA has a record in OSV (api.osv.dev),
  3. writes a dated coverage snapshot (how many advisories the public OSV database
     actually carries, by severity, with the oldest still-absent one), and
  4. updates a persistent first-seen ledger so repeated runs accrue the first real
     OSV ingestion-latency distribution for this category of software.

Public data only. No authentication, no secrets. Unauthenticated GitHub REST is
rate-limited (~60 req/h); the watched set is small enough to stay well under it.
Run: python census.py --out-dir /out --data-dir /data
"""
from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone

import requests

import lib

# Self-hosted-AI projects the local-ai-checkup / ai-stack-advisories work covers.
WATCHED_REPOS = [
    "ollama/ollama",
    "open-webui/open-webui",
    "comfyanonymous/ComfyUI",
    "vllm-project/vllm",
    "n8n-io/n8n",
    "langflow-ai/langflow",
    "FlowiseAI/Flowise",
    "BerriAI/litellm",
    "langgenius/dify",
    "infiniflow/ragflow",
    "Mintplex-Labs/anything-llm",
]

GH_API = "https://api.github.com"
OSV_API = "https://api.osv.dev/v1/vulns"
UA = "ai-stack-advisories-osv-census (+https://github.com/munimtechnologies/ai-stack-advisories)"


def _gh_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": UA}
    # Optional token only to raise the public rate limit; never required.
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return headers


def fetch_repo_advisories(repo: str, session: requests.Session) -> list[dict]:
    """Page through a repo's published security advisories."""
    out: list[dict] = []
    page = 1
    while True:
        url = f"{GH_API}/repos/{repo}/security-advisories"
        resp = session.get(
            url,
            headers=_gh_headers(),
            params={"per_page": 100, "page": page, "state": "published"},
            timeout=30,
        )
        if resp.status_code == 404:
            return out  # repo has no advisory listing enabled
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
        time.sleep(0.5)
    return out


def osv_present(ghsa_id: str, session: requests.Session) -> bool:
    """True if OSV returns a record for this GHSA, False on 404."""
    resp = session.get(f"{OSV_API}/{ghsa_id}", headers={"User-Agent": UA}, timeout=30)
    if resp.status_code == 404:
        return False
    resp.raise_for_status()
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--data-dir", default="data")
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    os.makedirs(args.data_dir, exist_ok=True)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    session = requests.Session()

    records: list[dict] = []
    per_repo: dict[str, int] = {}
    for repo in WATCHED_REPOS:
        advisories = fetch_repo_advisories(repo, session)
        per_repo[repo] = len(advisories)
        for adv in advisories:
            parsed = lib.parse_advisory(adv)
            if not parsed["ghsa_id"]:
                continue
            parsed["repo"] = repo
            parsed["osv_present"] = osv_present(parsed["ghsa_id"], session)
            records.append(parsed)
            time.sleep(0.2)

    snapshot = lib.summarize(records, now_iso)
    snapshot["per_repo_advisory_count"] = per_repo
    snapshot["watched_repos"] = WATCHED_REPOS

    # Persistent ledger (kept across runs via the compute lane's data_key).
    ledger_path = os.path.join(args.data_dir, "osv_ledger.json")
    ledger = {}
    if os.path.exists(ledger_path):
        with open(ledger_path, encoding="utf-8") as fh:
            ledger = json.load(fh)
    ledger = lib.merge_ledger(ledger, records, now_iso)
    latency = lib.ledger_latency_stats(ledger)

    date_tag = now_iso[:10]
    with open(os.path.join(args.out_dir, f"snapshot-{date_tag}.json"), "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)
    for path in (ledger_path, os.path.join(args.out_dir, "osv_ledger.json")):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(ledger, fh, indent=2)
    with open(os.path.join(args.out_dir, "latency-stats.json"), "w", encoding="utf-8") as fh:
        json.dump(latency, fh, indent=2)

    print(json.dumps({"snapshot": snapshot, "latency": latency}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
