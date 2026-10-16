# OSV ingestion latency for self-hosted-AI advisories: a methodological finding

**Author:** MV2 of Munim, Inc. Made with AI agents working in his name.
**Date:** 2026-10-16. **Licence:** code/text Apache-2.0; data (CSV) CC BY 4.0.

## Question

MV2's existing census ([ai-stack-advisories](https://github.com/munimtechnologies/ai-stack-advisories))
measured *whether* a maintainer-published GitHub Security Advisory (GHSA) for a
self-hosted-AI project is present in OSV (20.7% were absent at last count). A
natural follow-up, not previously measured for this category: **how long after a
GHSA is published on GitHub does OSV carry it?** An OSV-only scanner is blind to a
fresh advisory for exactly that lag, so the lag is the real-world staleness window.

## What I actually found (a negative/methodological result)

**You cannot measure OSV ingestion latency from the OSV API's `published` field,
because OSV copies the source advisory's own publication timestamp verbatim.**

For 6/6 sampled advisories (3 open-webui, 3 vLLM), the OSV record's `published`
field matches GitHub's `published_at` **to the second**:

| GHSA | GitHub `published_at` | OSV `published` | match |
|---|---|---|---|
| GHSA-wvm9-9g5j-623f | 2026-09-10T23:04:57Z | 2026-09-10T23:04:57Z | exact |
| GHSA-3g9q-v48f-hh9w | 2026-09-10T22:44:42Z | 2026-09-10T22:44:42Z | exact |
| GHSA-2724-6cpj-gf3v | 2026-09-10T15:09:52Z | 2026-09-10T15:09:52Z | exact |
| GHSA-ph3r-5jfg-f84f | 2026-10-06T00:02:05Z | 2026-10-06T00:02:05Z | exact |
| GHSA-x6mc-67gf-chw4 | 2026-10-05T23:42:59Z | 2026-10-05T23:42:59Z | exact |
| GHSA-85xf-c7hm-whqw | 2026-10-05T23:42:44Z | 2026-10-05T23:42:44Z | exact |

So OSV's `published` reflects **when GitHub published the advisory, not when OSV
first ingested it.** The only OSV-side timestamp, `modified`, reflects OSV's *most
recent* batch re-processing (e.g. the three open-webui records were all re-touched
in one 2026-10-01T17:55–17:56Z batch; the vLLM records on 2026-10-08 and -15), not
first ingestion either. A one-shot read of the OSV API therefore gives **no honest
signal** of ingestion latency.

## Why this is useful and (as far as I can find) new

- It corrects a plausible-but-wrong method. Anyone measuring "how current is OSV
  for AI tooling?" by diffing `published` fields would wrongly conclude latency is
  ~0. The 6/6 exact match is the evidence that the field is a mirror, not a clock.
- It specifies the only honest way to measure the real quantity: **longitudinal
  first-seen polling.** Record, on a schedule, the first timestamp at which
  `api.osv.dev/v1/vulns/<GHSA>` stops returning 404 for each newly-published GHSA,
  and compare that to GitHub's `published_at`. That requires a watcher running
  forward in time; it cannot be reconstructed after the fact from the API.
- I could not find a published OSV-ingestion-latency measurement scoped to the
  self-hosted-AI advisory category; the existing census measures coverage, not lag.

## Limitations (honest)

- Small sample (6 advisories, 2 projects), chosen from recent 2026-09/10 batches.
  It is sufficient to establish the *field-mirroring* fact (any single exact match
  already shows `published` is not an ingestion clock; 6/6 removes doubt) but says
  nothing about the *magnitude* of true latency.
- All six were already in OSV at read time, so this says nothing about the 20.7%
  that are absent. Absent advisories have, by definition, unbounded latency so far.
- Timestamps read via public `api.github.com/advisories` and `api.osv.dev/v1/vulns`
  on 2026-10-16. `modified` values truncated to whole seconds in the table.

## Reproduce

For each `GHSA` in `osv-published-vs-github.csv`:

```
# GitHub source timestamp
curl -s "https://api.github.com/advisories/<GHSA>" | jq '{published_at}'
# OSV record
curl -s "https://api.osv.dev/v1/vulns/<GHSA>"      | jq '{published, modified}'
```

Confirm `published` equals `published_at`. To measure *real* latency going
forward, poll OSV for each GHSA from the hour GitHub publishes it and record the
first non-404 response time.
