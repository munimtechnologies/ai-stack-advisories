<!--
Copyright 2026 Munim, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# OSV coverage verification — 2026-10-18

*A hand-verified spot-check for the self-hosted-AI OSV coverage census. Made with AI
agents working in MV2's name (MV2 of Munim, Inc.). Apache-2.0.*

## What this is

The census in this folder measures how completely [OSV](https://osv.dev) carries the
security advisories published for self-hosted AI tools. Its central hypothesis is that
many of these are **repo-level GitHub Security Advisories with no CVE ID**, which only
reach OSV after GitHub assigns/reviews them — so OSV-backed scanners miss them.

This note records a small sample checked **by hand on 2026-10-18 (UTC)** against the live
public APIs, so the finding stands on its own even before the full automated census runs.

## How to reproduce (no authentication needed)

```sh
# 1. List a project's published advisories and their CVE field:
curl -s "https://api.github.com/repos/open-webui/open-webui/security-advisories?state=published"
# 2. For each GHSA id, ask OSV whether it has a record (404 = absent):
curl -s -o /dev/null -w "%{http_code}\n" "https://api.osv.dev/v1/vulns/GHSA-q46m-r89w-j74p"
```

HTTP 200 means OSV has the advisory; HTTP 404 means it does not (yet). This is the same
rule the census tool uses (`osv_present()` in `census.py`).

## Results

**Positive control** (confirms the method distinguishes present from absent):

| GHSA | Alias | In OSV? |
|---|---|---|
| GHSA-jfh8-c2jp-5v3q (Log4Shell) | CVE-2021-44228 | ✅ present |

**open-webui/open-webui** (PyPI: `open-webui`):

| GHSA | Severity | CVE | In OSV? |
|---|---|---|---|
| GHSA-wvm9-9g5j-623f | Medium | **CVE-2026-88006** (PYSEC-2026-4129) | ✅ present |
| GHSA-q46m-r89w-j74p | High | — | ❌ not found |
| GHSA-vpq8-f445-hcq7 | High | — | ❌ not found |
| GHSA-qpqv-xwg8-cqpj | High | — | ❌ not found |
| GHSA-f9xp-mfmq-x6cg | High | — | ❌ not found |
| GHSA-2rr4-q6pg-m5g3 | Medium | — | ❌ not found |

**n8n-io/n8n** (npm: `n8n`):

| GHSA | Severity | CVE | In OSV? |
|---|---|---|---|
| GHSA-wvjj-qg37-pv73 | High | — | ❌ not found |
| GHSA-5qpp-pqww-h7fp | High | — | ❌ not found |
| GHSA-m7gv-mpg5-7c9v | High | — | ❌ not found |
| GHSA-fvv4-gmv9-xqf5 | High | — | ❌ not found |

## Finding

All **9 of 9** sampled *no-CVE* maintainer advisories across the two projects were absent
from OSV, while the one *CVE-bearing* advisory for the same project (open-webui) and the
control were both present. Several of the missing advisories are rated **High**. A team
relying on an OSV-backed scanner to flag Open WebUI or n8n issues would not see these.

## Honest limits

- Small sample: 11 lookups covering 2 of the 11 watched projects — not the full census.
- Point-in-time: `not found` means *not yet*; OSV may ingest any of these later. Only the
  full census (with its first-seen ledger) can measure ingestion latency.
- "No CVE" is the observed correlate; GitHub's review/mapping status is the likely true
  cause and was not inspected directly here.

---
MV2, Munim, Inc. · mv2@munimtech.com
