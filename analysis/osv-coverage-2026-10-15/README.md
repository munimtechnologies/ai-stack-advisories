# OSV coverage of self-hosted-AI apps' own GitHub security advisories

**Snapshot 2026-10-15 (21:41 UTC).** By MV2 of Munim, Inc. Made with AI.
Text and data CC BY 4.0; the census code (`census.py`) is Apache-2.0.

## Question

A self-hoster who scans dependencies with an OSV-keyed tool (osv-scanner, Trivy,
Grype, and anything else built on <https://osv.dev>) is only protected against the
advisories OSV actually carries. So: of the security advisories that these 11
self-hosted-AI projects' *own maintainers* have published on GitHub, how many would
such a scan see today?

## Method

- **Existence** — each repo's own
  `GET /repos/{owner}/{repo}/security-advisories?state=published`
  (cursor pagination via the RFC 5988 `Link` header; withdrawn advisories excluded;
  duplicate `(repo, GHSA)` rows dropped and counted).
- **Presence** — `GET https://api.osv.dev/v1/vulns/{GHSA}`; on 404, retry with the
  advisory's CVE id when it has one. HTTP 200 = present in OSV, 404 = absent from OSV
  (absent means "not in OSV at snapshot time", **not** "not a real vulnerability").
- Standard library only; 11 repos; every number in this file comes straight from
  `census.json`, produced by `census.py` whose pure functions are unit-tested offline
  (`test_census.py`, 18 tests, all passing). `fetch_status` was `ok` for all 11 repos
  and `osv_lookup_errors` was 0, so this is a complete snapshot, not a partial one.

## Result

| Repo | advisories | in OSV | absent | coverage |
|---|---:|---:|---:|---:|
| open-webui/open-webui | 165 | 145 | 20 | 87.9% |
| vllm-project/vllm | 104 | 80 | 24 | 76.9% |
| n8n-io/n8n | 225 | 152 | 73 | 67.6% |
| FlowiseAI/Flowise | 130 | 111 | 19 | 85.4% |
| langflow-ai/langflow | 37 | 36 | 1 | 97.3% |
| BerriAI/litellm | 17 | 14 | 3 | 82.4% |
| langgenius/dify | 21 | 16 | 5 | 76.2% |
| infiniflow/ragflow | 8 | 7 | 1 | 87.5% |
| Mintplex-Labs/anything-llm | 25 | 19 | 6 | 76.0% |
| comfyanonymous/ComfyUI | 4 | 4 | 0 | 100% |
| ollama/ollama | 0 | 0 | 0 | — |
| **all** | **736** | **584** | **152** | **79.3%** |

Reachable in OSV by GHSA id: **514**; by CVE alias only (the GHSA id itself 404s in
OSV): **70**; absent entirely: **152**.

Absent by severity: critical **7 / 96**, high **69 / 307**, medium **71 / 306**,
low **5 / 27**. Duplicates dropped: **0**.

Stale gap — absent **and** published more than 30 days ago: **62** advisories. The
oldest is `GHSA-7hpg-6pc7-cx86` (Mintplex-Labs/anything-llm, high), absent for
**526 days**. A notable one is `GHSA-435c-mg9p-fv22` / `CVE-2025-59434`
(FlowiseAI/Flowise, **critical**), absent for **398 days** despite carrying a CVE id.

## Reading it

- **OSV covers about four in five (79.3%) of these projects' own advisories, but one
  in five (152) is missing** — so an OSV-only scan of a self-hosted-AI stack has a
  real, measurable blind spot, concentrated in a few projects.
- **n8n dominates the gap**: 73 of the 152 absences (48%) are n8n's, and n8n has the
  lowest coverage (67.6%).
- **A separate GHSA-id gap**: 70 advisories are in OSV *only* under their CVE alias.
  A tool that keys solely on the GHSA id (without the CVE fallback this census uses)
  would also miss those 70, even though OSV has them.
- **The durable concern is the 62 stale gaps**, not the fresh ones. OSV ingests
  advisories with some lag, so a recently published advisory can be "absent" simply
  because OSV has not imported it yet. But a critical, CVE-bearing advisory absent for
  398 days, or a high-severity one absent for 526 days, is not ingestion lag.

This supersedes an earlier sibling run (`advisory-lag-v2`) that reported Dify 0/21,
AnythingLLM 0/25 and ComfyUI 0/4 in OSV. Those figures were wrong: that run looked up
only GHSA ids (no CVE fallback) and paged the GitHub endpoint with `page=`, fetching
the first 100 advisories repeatedly. This census follows the `Link` cursor, drops
duplicates (`duplicates_dropped` = 0 here) and adds the CVE fallback, so prefer these
numbers.

## Limits

- A single snapshot in time. Re-running on another day will move the counts,
  especially for recently published advisories (OSV ingestion lag).
- The unauthenticated GitHub API returns published advisories only.
- "Absent" is decided by OSV's `vulns/{id}` lookup on the GHSA id and, as a fallback,
  the CVE id. If OSV indexes an advisory under some other identifier, it would be
  counted absent here; the stale-gap list is the right place to spot-check that.
- Coverage is measured per advisory, not per affected version.

## Prior art

General work exists on the GitHub Security Advisory review pipeline and on OSV's
overall coverage of random open-source vulnerabilities (OSV ~93% in published
benchmarks), but neither answers this per-application question for the self-hosted-AI
category specifically. That per-project, OSV-vs-maintainer-advisory view is what this
census adds.

## Reproduce

```
python -I -m unittest -v        # 18 offline tests
python -I census.py --out-dir out
```

`census.json` in this folder is the exact machine output of that second command at the
snapshot above (`rows` = every advisory with its OSV status; `stale_gap` = the 62
durable gaps; `totals`, `by_repo`, `by_via`, `by_severity` = the aggregates).
