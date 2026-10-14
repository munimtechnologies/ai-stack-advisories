"""Self-hosted AI stack vulnerability check: an Apify Actor published by MV2 of Munim, Inc.

Input: a list of components such as "ollama@0.34.5", "n8n 2.40.0" or "pypi:requests==2.31.0".
Output: one dataset item per component, listing the advisories that affect that exact version
and the version to update to. Combines a curated list (advisories.json, including advisories
that have no CVE ID and are missing from OSV.dev and the GitHub Advisory Database) with a live
OSV.dev query. Read-only: it never connects to the user's servers.
"""

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from apify import Actor

HERE = Path(__file__).resolve().parent
CURATED = json.loads((HERE / "advisories.json").read_text(encoding="utf-8"))
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_COMPONENTS = 500

# Checked when a run starts with no components (API calls, scheduled tests), so it still shows real output.
EXAMPLE_COMPONENTS = ["ollama@0.34.5", "open-webui@0.11.2", "vllm@0.30.0", "n8n@2.40.0", "flowise@3.1.4"]

# Curated product key -> OSV (ecosystem, package name), or None when there is no package.
PRODUCT_PACKAGES = {
    "ollama": ("Go", "github.com/ollama/ollama"),
    "openwebui": ("PyPI", "open-webui"),
    "vllm": ("PyPI", "vllm"),
    "langflow": ("PyPI", "langflow"),
    "flowise": ("npm", "flowise"),
    "litellm": ("PyPI", "litellm"),
    "n8n": ("npm", "n8n"),
    "dify": None,
    "ragflow": None,
    "anythingllm": None,
    "comfyui": None,
    "mcpinspector": ("npm", "@modelcontextprotocol/inspector"),
}

# Normalised name -> curated product key.
PRODUCT_ALIASES = {
    "ollama": "ollama",
    "github.com/ollama/ollama": "ollama",
    "open-webui": "openwebui",
    "openwebui": "openwebui",
    "vllm": "vllm",
    "vllm-openai": "vllm",
    "vllm/vllm-openai": "vllm",
    "langflow": "langflow",
    "flowise": "flowise",
    "litellm": "litellm",
    "litellm-proxy": "litellm",
    "n8n": "n8n",
    "dify": "dify",
    "langgenius/dify": "dify",
    "dify-api": "dify",
    "langgenius/dify-api": "dify",
    "ragflow": "ragflow",
    "infiniflow/ragflow": "ragflow",
    "rag-flow": "ragflow",
    "anythingllm": "anythingllm",
    "anything-llm": "anythingllm",
    "mintplexlabs/anythingllm": "anythingllm",
    "mintplex-labs/anything-llm": "anythingllm",
    "comfyui": "comfyui",
    "comfy-ui": "comfyui",
    "mcp-inspector": "mcpinspector",
    "mcpinspector": "mcpinspector",
    "@modelcontextprotocol/inspector": "mcpinspector",
    "modelcontextprotocol/inspector": "mcpinspector",
}

ECOSYSTEMS = {
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI",
    "npm": "npm", "node": "npm",
    "go": "Go", "golang": "Go",
    "crates": "crates.io", "cargo": "crates.io", "crates.io": "crates.io",
    "maven": "Maven",
    "rubygems": "RubyGems", "gem": "RubyGems",
    "nuget": "NuGet",
    "packagist": "Packagist", "composer": "Packagist",
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}

COMPONENT_RE = re.compile(r"^(.*?)\s*(?:==|@|:|\s)\s*v?(\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.+-]*)?)$")


def vtuple(v):
    """'1.2.3', 'v1.2', '2.0.0-rc.1' -> (1, 2, 3) style tuple, or None."""
    m = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v or "").strip())
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def parse_component(raw):
    """Return (ecosystem or None, name, version) or raise ValueError."""
    s = str(raw or "").strip()
    eco = None
    m = re.match(r"^([A-Za-z.]+):(?!//)(.+)$", s)
    if m and m.group(1).lower() in ECOSYSTEMS:
        eco = ECOSYSTEMS[m.group(1).lower()]
        s = m.group(2).strip()
    m = COMPONENT_RE.match(s)
    if not m or not m.group(1).strip():
        raise ValueError("Write each component as name@version, for example ollama@0.34.5 or pypi:requests@2.31.0.")
    return eco, m.group(1).strip(), m.group(2)


def curated_hits(product_key, version):
    v = vtuple(version)
    hits = []
    for item in CURATED["products"][product_key]["items"]:
        if item.get("only"):
            if not any(vtuple(x) == v for x in item["only"]):
                continue
        else:
            if item.get("introduced") and v < vtuple(item["introduced"]):
                continue
            if item.get("fixed") and v >= vtuple(item["fixed"]):
                continue
            # Advisories with no fixed release name the last affected version instead.
            if item.get("lastAffected") and v > vtuple(item["lastAffected"]):
                continue
        note = None
        if item.get("kind") == "windows":
            note = "Windows builds only."
        elif item.get("kind") == "feature":
            note = "Only if the optional feature named in the summary is used."
        hits.append({
            "id": item["ids"][0],
            "aliases": item["ids"][1:],
            "summary": item["summary"],
            "severity": item.get("severity"),
            "fixedIn": item.get("fixed"),
            "url": item["url"],
            "source": "curated",
            "notInPublicDatabases": item.get("inPublicDatabases") is False,
            "note": note,
        })
    return hits


async def osv_query(client, ecosystem, name, version):
    vulns, token = [], None
    while True:
        body = {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
        if token:
            body["page_token"] = token
        r = await client.post(OSV_QUERY_URL, json=body, timeout=30)
        r.raise_for_status()
        data = r.json()
        vulns.extend(data.get("vulns") or [])
        token = data.get("next_page_token")
        if not token:
            return vulns


def osv_severity(vuln):
    sev = (vuln.get("database_specific") or {}).get("severity")
    if sev:
        return str(sev).upper()
    for s in vuln.get("severity") or []:
        if s.get("score"):
            return s["score"]
    return None


def osv_fixed(vuln, ecosystem, name, version):
    """Smallest fixed version above the queried version, for this package."""
    v = vtuple(version)
    best = None
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or str(pkg.get("name", "")).lower() != name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                fx = ev.get("fixed")
                t = vtuple(fx)
                if t and t > v and (best is None or t < vtuple(best)):
                    best = fx
    return best


def osv_hit(vuln, ecosystem, name, version):
    vid = vuln.get("id")
    return {
        "id": vid,
        "aliases": vuln.get("aliases") or [],
        "summary": vuln.get("summary") or (vuln.get("details") or "")[:300],
        "severity": osv_severity(vuln),
        "fixedIn": osv_fixed(vuln, ecosystem, name, version),
        "url": f"https://osv.dev/vulnerability/{vid}",
        "source": "osv.dev",
        "notInPublicDatabases": False,
        "note": None,
    }


def merge(curated, osv):
    """Keep every OSV entry. Keep a curated entry unless all its IDs are already covered by OSV."""
    covered = set()
    for h in osv:
        covered.add(h["id"])
        covered.update(h["aliases"])
    kept = [h for h in curated if not all(i in covered for i in [h["id"], *h["aliases"]])]
    return kept + osv


def max_severity(hits):
    best = None
    for h in hits:
        s = h.get("severity")
        if isinstance(s, str) and s.upper() in SEVERITY_RANK:
            if best is None or SEVERITY_RANK[s.upper()] > SEVERITY_RANK[best]:
                best = s.upper()
    return best


def upgrade_to(hits):
    best = None
    for h in hits:
        if h.get("fixedIn") and (best is None or vtuple(h["fixedIn"]) > vtuple(best)):
            best = h["fixedIn"]
    return best


async def check_component(client, raw, use_osv):
    result = {"component": raw, "checkedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "curatedDataAsOf": CURATED["checked"]}
    try:
        eco, name, version = parse_component(raw)
    except ValueError as e:
        return {**result, "status": "error", "error": str(e)}

    product_key = None
    if eco is None:
        product_key = PRODUCT_ALIASES.get(re.sub(r"[\s_]+", "-", name.lower()))
        if product_key is None:
            return {**result, "status": "error", "name": name, "version": version,
                    "error": "Unknown product. Supported without a prefix: " + ", ".join(
                        p["name"] for p in CURATED["products"].values())
                    + ". For any other package, prefix its ecosystem, for example pypi:requests@2.31.0 or npm:express@4.17.1."}
        package = PRODUCT_PACKAGES.get(product_key)
        eco_q, name_q = package if package else (None, None)
        display = CURATED["products"][product_key]["name"]
    else:
        eco_q, name_q, display = eco, name, name

    curated = curated_hits(product_key, version) if product_key else []
    osv, osv_error = [], None
    if use_osv and eco_q:
        try:
            vulns = await osv_query(client, eco_q, name_q, version)
            osv = [osv_hit(x, eco_q, name_q, version) for x in vulns]
        except (httpx.HTTPError, ValueError) as e:
            osv_error = f"OSV.dev query failed: {e}"

    hits = merge(curated, osv)
    hits.sort(key=lambda h: -SEVERITY_RANK.get(str(h.get("severity") or "").upper(), 0))
    unpatched = sum(1 for h in hits if not h.get("fixedIn"))
    out = {
        **result,
        "product": display,
        "ecosystem": eco_q,
        "package": name_q,
        "version": version,
        "status": "affected" if hits else "no known advisories",
        "advisoryCount": len(hits),
        "maxSeverity": max_severity(hits),
        "upgradeTo": upgrade_to(hits),
        "noFixedReleaseCount": unpatched,
        "notInPublicDatabasesCount": sum(1 for h in hits if h["notInPublicDatabases"]),
        "advisories": hits,
    }
    if osv_error:
        out["osvError"] = osv_error
    if hits and not out["upgradeTo"]:
        out["note"] = "No fixed version is listed; update to the latest release and follow the advisories' mitigations."
    elif hits:
        out["note"] = f"Update to {out['upgradeTo']} or newer; the latest release is best."
        if unpatched:
            out["note"] += f" {unpatched} of these advisories list no fixed release yet, so also follow their mitigations."
    return out


async def safe_check(client, raw, use_osv):
    """One odd component becomes an error item instead of failing the whole run."""
    try:
        return await check_component(client, raw, use_osv)
    except Exception as e:  # noqa: BLE001
        Actor.log.exception(f"Checking {raw!r} failed")
        return {"component": raw, "checkedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "curatedDataAsOf": CURATED["checked"], "status": "error",
                "error": f"Internal error while checking this component ({type(e).__name__}). Please report it at https://github.com/munimv2/ai-stack-advisories/issues."}


async def main():
    async with Actor:
        inp = await Actor.get_input() or {}
        raw = inp.get("components") or []
        if isinstance(raw, str):
            raw = raw.splitlines()
        components = [str(c).strip() for c in raw if str(c).strip()]
        use_osv = inp.get("useOsv", True)
        only_affected = inp.get("onlyAffected", False)
        example_run = not components
        if example_run:
            Actor.log.warning("No components given, so checking example components. Add your own, for example ollama@0.34.5.")
            components = list(EXAMPLE_COMPONENTS)
        if len(components) > MAX_COMPONENTS:
            Actor.log.warning(f"Only the first {MAX_COMPONENTS} components are checked.")
            components = components[:MAX_COMPONENTS]

        sem = asyncio.Semaphore(8)
        headers = {"User-Agent": "mv2-ai-stack-advisories (Apify Actor by MV2 of Munim, Inc.)"}
        async with httpx.AsyncClient(headers=headers) as client:
            async def run(c):
                async with sem:
                    return await safe_check(client, c, use_osv)
            results = await asyncio.gather(*(run(c) for c in components))

        pushed = 0
        for r in results:
            if only_affected and r["status"] == "no known advisories":
                continue
            await Actor.push_data(r)
            pushed += 1
        affected = sum(1 for r in results if r["status"] == "affected")
        msg = f"Checked {len(results)} components: {affected} affected. {pushed} items saved."
        if example_run:
            msg = "No components given, so these are example results. " + msg
        await Actor.set_status_message(msg)


if __name__ == "__main__":
    asyncio.run(main())
