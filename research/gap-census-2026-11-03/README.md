# Releases between an advisory's affected range and its fix (census, 3 November 2026)

By MV2 of Munim, Inc., made with AI agents. Code: Apache-2.0. Data and text: CC BY 4.0.

## Question

Some GitHub security advisories give an affected range that stops *below* the version they name as patched.
For example, a vLLM advisory says affected `<= 0.25.1` but patched `0.32.0`. Releases 0.26.0 to 0.31.0 fall in
between. Are they affected? The advisory doesn't say. A scanner that reads only the range would report them clean,
and one that reads only the patched version would flag them.

This pattern is already known. GitHub's
[best practices for writing repository security advisories](https://docs.github.com/code-security/repository-security-advisories/best-practices-for-writing-repository-security-advisories)
warn against it, and single cases have been fixed in github/advisory-database. What we couldn't find was a count for
these projects, or a check of how OSV.dev reads such advisories. That is what this census adds.

We counted how often this happens for the 12 self-hosted AI projects that
[ai-stack-advisories](../../README.md) covers. Then we checked whether OSV.dev, and this feed itself, flag the
releases that fall in the gap.

## Method

`gap_census.py` (standard library only, tests in `test_gap_census.py`, 17 passing):

1. It reads every published GitHub repository security advisory of the 12 projects.
2. It keeps advisories that give one affected range and one patched version for the project's own package.
3. It finds the advisories whose range ends below the patched version (a "gap").
4. It lists the project's published stable releases inside each gap, from PyPI, npm or `git ls-remote --tags`.
   An advisory with a blank or misspelled package name uses the project's own package.
5. For each of those releases it records whether OSV.dev's record for the same GHSA ID marks it affected, and
   whether this feed (v1.2.3) flags it.

The run used 17 unauthenticated GitHub API calls and finished at 2026-11-03T15:04Z. The full output is in
`gap_census.txt`.

## Result

| | count |
|---|---|
| published advisories, 12 projects | 779 |
| with one range and one patched version | 519 |
| range ends below the patched version (gap) | 262 |
| gap holds at least one published stable release | **41** (299 releases in total) |
| of those 41: OSV.dev has a record and marks **every** in-gap release affected | 26 |
| of those 41: OSV.dev marks some or none of them | **0** |
| of those 41: no OSV.dev record for the GHSA ID when checked | 15 |
| of those 41: this feed flags every in-gap release | 41 |

By project, the 41 are: vLLM 12 (113 releases), Langflow 11 (90), Flowise 9 (44), Dify 7 (32), Open WebUI 1 (19),
RAGFlow 1 (1). Ollama, n8n, LiteLLM, AnythingLLM, ComfyUI and MCP Inspector had none. The largest gap is
GHSA-mm38-5g96-7j6x (vLLM, high): affected `<= 0.8.5`, patched `>= 0.25.0`, with 32 stable releases between them.

## What this means

This is a **negative result**. We found no case where OSV.dev reports an in-gap release as clean. Whenever OSV.dev
has the advisory, it takes the cautious reading: every release before the patched version is affected. This feed
does the same. So the gaps are inconsistencies inside the advisories, not missed warnings in OSV-based scanners.

There is one limit. For 15 of the 41, OSV.dev had no record under the GHSA ID when we checked, so a scanner that
reads only OSV.dev would not report those advisories at all, gap or not. This census does not try to explain that.
We also don't know which reading is *true* for any in-gap release: only the project can say whether 0.26.0 to 0.31.0
are really affected.

## Files

- `gap_census.py`, `test_gap_census.py`: the census and its tests.
- `gap_census.txt`: per-project counts, the total, and one `GAP` line per advisory with releases in its gap
  (range, patched version, first and last in-gap release, OSV state, whether the feed flags them all).
- `gap_census.json`: the same rows as data.

Corrections are welcome as issues on this repository.
