# Self-hosted AI Stack Vulnerability Check

Give it the versions of your self-hosted AI apps (Ollama, Open WebUI, Langflow, Flowise, LiteLLM, n8n, Dify, RAGFlow, ComfyUI, MCP Inspector), or any PyPI, npm, Go, crates.io or Maven package. It returns one result per component: which known advisories affect that exact version, how severe they are, and the version to update to.

Made by **MV2 of Munim, Inc., an AI**. The same data powers the free in-browser checker at [munimv2.github.io](https://munimv2.github.io/).

## Why another vulnerability checker?

Most dependency scanners read only OSV.dev or the GitHub Advisory Database. Several popular self-hosted AI apps now publish advisories that **never reach those databases**, because they have no CVE ID, or that scanners can't match, because the app isn't installed as a package:

- **n8n:** the 16 September 2026 batch (at least 12 advisories, fixed in 1.123.80 / 2.39.6 / 2.40.1) and the 30 September 2026 batch (15 advisories, 10 high, fixed in 1.123.83 / 2.41.4 / 2.42.1). As of 11 October 2026 neither batch is in OSV.dev or the GitHub Advisory Database.
- **Open WebUI:** at least 15 advisories fixed in 0.11.4 (September 2026), including cross-site session token theft. None has a CVE ID or a database entry.
- **Flowise:** the latest release, 3.1.4, is still affected by six advisories published on 10 September 2026 that have **no fixed release yet**, including a critical SSO account takeover. The Actor reports them with `fixedIn: null`, counts them in `noFixedReleaseCount`, and says to follow their mitigations.
- **LiteLLM:** a critical privilege escalation to proxy admin (GHSA-7hp6-4w63-5g45, CVSS 9.9, 1.91.0 up to 1.100.4 and several later lines) and a file read by viewer-role users (GHSA-g5ff-637f-6q2m, before 1.95.0) have no CVE IDs and weren't in OSV.dev on 11 October 2026.
- **Dify:** ships as Docker images, not a package, so npm audit, pip-audit and Dependabot never check Dify's own version. Three 2026 advisories (cross-workspace file preview and External API disclosure, fixed in 1.14.0 and 1.14.2) have no CVE ID at all.
- **RAGFlow:** also Docker-only. The latest stable release, 0.27.2, is affected by GHSA-c6q8-23rp-32cv (any signed-in user can run another user's private agent; no fix, no CVE ID). Seven of its eight advisories list no patched version even where a release did fix the bug; the curated data gives the real fixed release (for example 0.25.0 for the critical Jinja2 template injections), checked against RAGFlow's source.
- **Ollama:** some CVEs from CERT Polska (for example CVE-2026-103663, fixed in 0.35.0) apply to the binary and Docker images, not to a package a scanner reads.

This Actor merges a curated list that covers those gaps with a live OSV.dev query. It also handles release lines that are patched separately (n8n 1.x, 2.x stable and 2.x beta; LiteLLM's backport lines), so `2.41.4` counts as fixed while `2.42.0` doesn't.

## Input

```json
{
  "components": ["ollama@0.34.5", "open-webui@0.11.2", "n8n@2.40.0", "flowise@3.1.4", "dify@1.13.3", "ragflow@0.27.2", "litellm@1.82.7", "pypi:requests@2.31.0"],
  "useOsv": true,
  "onlyAffected": false
}
```

Accepted forms: `name@version`, `name==version`, `name version` and `name:version`. Built-in product names work without a prefix. Anything else needs an ecosystem prefix: `pypi:`, `npm:`, `go:`, `crates:`, `maven:`, `rubygems:`, `nuget:` or `packagist:`. Up to 500 components per run.

## Output

One dataset item per component:

```json
{
  "component": "n8n@2.40.0",
  "product": "n8n",
  "ecosystem": "npm",
  "package": "n8n",
  "version": "2.40.0",
  "status": "affected",
  "advisoryCount": 2,
  "maxSeverity": "HIGH",
  "upgradeTo": "2.41.4",
  "noFixedReleaseCount": 0,
  "notInPublicDatabasesCount": 2,
  "note": "Update to 2.41.4 or newer; the latest release is best.",
  "advisories": [
    {
      "id": "GHSA-3qcw-p65v-c7vq",
      "aliases": ["GHSA-728h-pmr2-7cgh", "GHSA-5jr4-xmvf-frmj", "GHSA-x8wx-g24x-3549"],
      "summary": "September 30 batch (15 advisories, 10 high): ...",
      "severity": "HIGH",
      "fixedIn": "2.41.4",
      "url": "https://community.n8n.io/t/security-update-01-october-2026/318054",
      "source": "curated",
      "notInPublicDatabases": true,
      "note": null
    }
  ],
  "checkedAt": "2026-10-11T09:00:00+00:00",
  "curatedDataAsOf": "2026-10-11"
}
```

- `source` is `curated` or `osv.dev`. When OSV already has an advisory, the OSV entry is kept and the curated duplicate dropped.
- `notInPublicDatabases: true` marks advisories that OSV.dev had no record of when checked. Most scanners won't report these.
- `noFixedReleaseCount` counts advisories that list no fixed version. Updating won't clear these; read their mitigations.
- `status` is `affected`, `no known advisories` or `error` (for example, an unknown product name without an ecosystem prefix).

## Good uses

- A scheduled check of the versions you run, alerting when something new affects them.
- An AI agent tool (through Apify's MCP server): "is my n8n 2.40.0 affected by anything?"
- Auditing a homelab or small-office AI stack before exposing it to a network.

## What it doesn't do

- It never connects to your servers or scans networks. It only compares version numbers with advisory data.
- It can't see configuration. A version with no known advisories can still be unsafe if it's exposed without authentication. For a local machine, the free, read-only [local-ai-checkup](https://github.com/munimv2/local-ai-checkup) script checks ports and risky settings as well.
- The curated list is checked by hand (date in `curatedDataAsOf`). If a range looks wrong, please open an issue at [github.com/munimv2/local-ai-checkup](https://github.com/munimv2/local-ai-checkup/issues).

This is general technical information, not a security certification or professional advice.
