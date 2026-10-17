# OSV coverage census & ingestion-latency ledger

Part of [ai-stack-advisories](https://github.com/munimtechnologies/ai-stack-advisories).
Licensed under **Apache-2.0**. Built by MV2 of Munim, Inc. — **made with AI**.

## What it measures

Security scanners that many teams rely on (pip-audit, Trivy, Grype, osv-scanner)
resolve vulnerabilities through [OSV](https://osv.dev). But the self-hosted-AI
projects people run locally — Ollama, Open WebUI, ComfyUI, vLLM, n8n, Langflow,
Flowise, LiteLLM, Dify, RAGFlow, AnythingLLM — publish many advisories as
**repo-level GitHub advisories with no CVE ID**, which only reach OSV once GitHub
reviews them into the global database. This tool measures, from public data only:

1. **Coverage** — of every published advisory for these projects, how many OSV
   actually carries today, broken down by severity, with the oldest still-absent one.
2. **Ingestion latency** — a persistent first-seen ledger records, per advisory, when
   GitHub published it and the first run at which OSV began returning a record. Run
   repeatedly, this accrues the first real OSV *ingestion-latency distribution* for
   this category of software.

## Why this is new

Published OSV coverage/latency studies (e.g. the OpenSSF OSV work and academic
vulnerability-database timeliness papers) look at ecosystems as a whole (npm, PyPI,
Go). We are not aware of a measurement scoped to self-hosted-AI applications, where
the no-CVE repo-advisory path makes the gap materially larger. The latency half must
be *witnessed* forward in time: OSV stamps an ingested GHSA with GitHub's original
publish time, so a single snapshot cannot recover latency — only repeated polling can.

## Honest limits

- A snapshot `absent_from_osv` is a point-in-time count; an advisory can appear in OSV
  later. The ledger corrects this the next run it is seen present.
- Latency is only defined for advisories we observed flip from absent → present.
  Advisories already in OSV at first sight are right-censored (a lower bound), not a
  measured latency, and are excluded from the latency stats.
- Unauthenticated GitHub REST is rate-limited (~60 req/h); set `GITHUB_TOKEN` to raise
  it. The watched set is small enough to run unauthenticated.

## Run

```bash
pip install -r requirements.txt
python census.py --out-dir out --data-dir data
```

Outputs: `snapshot-YYYY-MM-DD.json`, `osv_ledger.json`, `latency-stats.json`.

## Tests

```bash
python -m unittest -v test_lib
```

`lib.py` is pure and stdlib-only; the tests run offline with no network.
