#!/usr/bin/env python3
"""Find self-hosted AI apps with known advisories in a repository's compose files, Kubernetes
manifests, Dockerfiles, requirements files and package.json.

Part of ai-stack-advisories by MV2 of Munim, Inc. Uses only the Python standard library
and the curated advisories.json next to this file (the same data as https://munimv2.github.io/),
so it works offline and sends nothing anywhere. It reads version pins only; it never connects to
your servers.

    python3 scan_stack.py [paths ...] [--fail-on affected|never] [--json]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Docker image name (registry host and tag removed, lowercase) -> curated product key.
IMAGES = {
    "ollama/ollama": "ollama",
    "open-webui/open-webui": "openwebui",
    "vllm/vllm-openai": "vllm",
    "n8nio/n8n": "n8n",
    "langgenius/dify-api": "dify",
    "langgenius/dify-web": "dify",
    "infiniflow/ragflow": "ragflow",
    "mintplexlabs/anythingllm": "anythingllm",
    "langflowai/langflow": "langflow",
    "flowiseai/flowise": "flowise",
    "berriai/litellm": "litellm",
    "berriai/litellm-database": "litellm",
}
PYPI = {"open-webui": "openwebui", "vllm": "vllm", "langflow": "langflow", "litellm": "litellm"}
NPM = {"n8n": "n8n", "flowise": "flowise", "@modelcontextprotocol/inspector": "mcpinspector"}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}
MAX_FILE_BYTES = 2_000_000
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}

IMAGE_LINE_RE = re.compile(r"""^\s*-?\s*image:\s*["']?([^"'\s#]+)""")
FROM_LINE_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)", re.IGNORECASE)
REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*v?(\d[0-9A-Za-z.+-]*)")
VERSION_IN_TAG_RE = re.compile(r"(?<![0-9])v?(\d+\.\d+(?:\.\d+)?)")
NPM_SPEC_RE = re.compile(r"^\s*([\^~=v]*)\s*(\d+\.\d+(?:\.\d+)?)")
VAR_DEFAULT_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=]([^}]*)\}")


def vtuple(v):
    """'1.2.3', 'v1.2', '2.0.0-rc.1' -> (1, 2, 3) style tuple, or None."""
    m = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v or "").strip())
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def parse_image(ref):
    """'ghcr.io/open-webui/open-webui:v0.11.2' -> ('open-webui/open-webui', 'v0.11.2')."""
    ref = VAR_DEFAULT_RE.sub(lambda m: m.group(1), ref.strip()).split("@", 1)[0]
    name, tag = ref, None
    if ref.rfind(":") > ref.rfind("/"):
        name, tag = ref[:ref.rfind(":")], ref[ref.rfind(":") + 1:]
    parts = name.lower().split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    if parts and parts[0] == "library":
        parts = parts[1:]
    return "/".join(parts), tag


def tag_version(tag):
    """'main-v1.74.0-stable' -> '1.74.0'; 'latest', 'main', 'cuda' or None -> None."""
    if not tag or "$" in tag:
        return None
    m = VERSION_IN_TAG_RE.search(tag)
    return m.group(1) if m else None


def affecting(items, version, skip_windows=False):
    """Curated advisories that affect this exact version (same rules as the Apify Actor)."""
    v = vtuple(version)
    hits = []
    for item in items:
        if skip_windows and item.get("kind") == "windows":
            continue
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
        hits.append(item)
    return hits


def make_finding(data, file, line, kind, ref, key, version, is_range=False):
    product = data["products"].get(key)
    if product is None:
        return None
    out = {"file": file, "line": line, "kind": kind, "ref": ref, "product": key, "name": product["name"],
           "version": version, "range": is_range}
    if version is None:
        return {**out, "status": "unpinned", "advisories": [], "upgradeTo": None, "noFixedRelease": 0}
    hits = affecting(product["items"], version, skip_windows=(kind == "image"))
    advisories = [{
        "id": h["ids"][0],
        "aliases": h["ids"][1:],
        "severity": h.get("severity"),
        "fixedIn": h.get("fixed"),
        "summary": h["summary"],
        "url": h["url"],
        "notInPublicDatabases": h.get("inPublicDatabases") is False,
        "onlyIfFeatureUsed": h.get("kind") == "feature",
    } for h in hits]
    advisories.sort(key=lambda a: -SEVERITY_RANK.get(str(a["severity"] or "").upper(), 0))
    fixes = [a["fixedIn"] for a in advisories if a["fixedIn"]]
    return {**out, "status": "affected" if advisories else "ok", "advisories": advisories,
            "upgradeTo": max(fixes, key=vtuple) if fixes else None,
            "noFixedRelease": sum(1 for a in advisories if not a["fixedIn"])}


def file_kind(path):
    n = path.name.lower()
    if n.endswith((".yml", ".yaml")):
        return "yaml"
    if n in ("dockerfile", "containerfile") or n.startswith("dockerfile.") or n.endswith(".dockerfile"):
        return "docker"
    if re.match(r"(requirements|constraints).*\.txt$", n):
        return "req"
    if n == "package.json":
        return "npm"
    return None


def scan_text(data, file, kind, text):
    found = []
    lines = text.splitlines()
    if kind in ("yaml", "docker"):
        line_re = IMAGE_LINE_RE if kind == "yaml" else FROM_LINE_RE
        for n, line in enumerate(lines, 1):
            m = line_re.match(line)
            if not m:
                continue
            name, tag = parse_image(m.group(1))
            key = IMAGES.get(name)
            if key:
                found.append(make_finding(data, file, n, "image", m.group(1), key, tag_version(tag)))
    elif kind == "req":
        for n, line in enumerate(lines, 1):
            m = REQ_LINE_RE.match(line)
            if not m:
                continue
            key = PYPI.get(m.group(1).lower().replace("_", "-"))
            if key:
                found.append(make_finding(data, file, n, "pypi", line.strip(), key, m.group(2)))
    elif kind == "npm":
        try:
            pkg = json.loads(text)
        except ValueError:
            return []
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = pkg.get(section) if isinstance(pkg, dict) else None
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                key = NPM.get(name)
                if not key or not isinstance(spec, str):
                    continue
                m = NPM_SPEC_RE.match(spec)
                line = next((i for i, x in enumerate(lines, 1) if '"%s"' % name in x), 1)
                is_range = bool(m and ("^" in m.group(1) or "~" in m.group(1)))
                found.append(make_finding(data, file, line, "npm", f"{name}@{spec}", key,
                                          m.group(2) if m else None, is_range))
    return [f for f in found if f]


def display_path(path):
    try:
        return os.path.relpath(path).replace(os.sep, "/")
    except ValueError:
        return str(path).replace(os.sep, "/")


def iter_files(paths):
    for p in paths:
        p = Path(p)
        if p.is_file():
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for f in sorted(files):
                yield Path(root) / f


def scan_paths(paths, data):
    findings = []
    for path in iter_files(paths):
        kind = file_kind(path)
        if not kind:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(data, display_path(path), kind, text))
    return findings


def describe(f):
    what = f"{f['name']} {f['version'] or ''}".strip() + f" ({f['ref']})"
    if f["status"] == "unpinned":
        return what + ": no exact version, so it can't be checked. Pin a version and update it deliberately."
    if f["status"] == "ok":
        return what + ": no known advisories in the curated list."
    n = len(f["advisories"])
    msg = what + f": {n} known advisor{'y' if n == 1 else 'ies'}"
    if f["upgradeTo"]:
        msg += f"; update to {f['upgradeTo']} or newer"
    if f["noFixedRelease"]:
        msg += f"; {f['noFixedRelease']} with no fixed release yet (follow their mitigations)"
    if f["range"]:
        msg += ". This is a version range, so the lowest version it allows was checked; your lockfile may pin a newer one"
    return msg + "."


def format_text(findings, data):
    out = []
    for f in findings:
        out.append(f"{f['file']}:{f['line']}  {describe(f)}")
        for a in f["advisories"]:
            extra = []
            if a["severity"]:
                extra.append(str(a["severity"]).lower())
            if a["notInPublicDatabases"]:
                extra.append("not in OSV when checked")
            if a["onlyIfFeatureUsed"]:
                extra.append("only if that feature is used")
            tail = f" [{', '.join(extra)}]" if extra else ""
            out.append(f"    - {a['id']}{tail}: {a['summary']} {a['url']}")
    affected = sum(1 for f in findings if f["status"] == "affected")
    out.append(f"Checked {len(findings)} pinned self-hosted AI component(s): {affected} affected. "
               f"Curated data as of {data.get('checked', '?')}; by MV2 of Munim, Inc., "
               "https://github.com/munimtechnologies/ai-stack-advisories")
    return "\n".join(out)


def _esc_data(s):
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s):
    return _esc_data(s).replace(":", "%3A").replace(",", "%2C")


def annotations(findings):
    levels = {"affected": "error", "unpinned": "notice"}
    out = []
    for f in findings:
        level = levels.get(f["status"])
        if level:
            title = f"{f['name']} {f['version'] or ''}".strip()
            out.append(f"::{level} file={_esc_prop(f['file'])},line={f['line']},title={_esc_prop(title)}::"
                       f"{_esc_data(describe(f))}")
    return out


def step_summary(findings, data):
    rows = ["### Self-hosted AI stack advisories", "",
            "| File | Component | Status | Update to |", "|---|---|---|---|"]
    for f in findings:
        status = f["status"] if f["status"] != "affected" else f"affected ({len(f['advisories'])})"
        rows.append(f"| `{f['file']}:{f['line']}` | {f['name']} {f['version'] or '(unpinned)'} | {status} | "
                    f"{f['upgradeTo'] or ('no fixed release' if f['noFixedRelease'] else '')} |")
    rows += ["", f"Curated data as of {data.get('checked', '?')}, including advisories with no CVE ID. "
             "Made by MV2 of Munim, Inc.: https://munimv2.github.io/"]
    return "\n".join(rows) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check pinned versions of self-hosted AI apps against known advisories.")
    ap.add_argument("paths", nargs="*", default=["."], help="files or folders to scan (default: .)")
    ap.add_argument("--fail-on", choices=["affected", "never"], default="affected",
                    help="exit 1 when a pinned version has known advisories (default), or never")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--advisories", default=str(HERE / "advisories.json"), help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    data = json.loads(Path(args.advisories).read_text(encoding="utf-8"))
    findings = scan_paths(args.paths or ["."], data)

    if args.json:
        print(json.dumps({"curatedDataAsOf": data.get("checked"), "findings": findings}, indent=2))
    else:
        print(format_text(findings, data))
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for a in annotations(findings):
            print(a)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(step_summary(findings, data))

    affected = any(f["status"] == "affected" for f in findings)
    return 1 if affected and args.fail_on == "affected" else 0


if __name__ == "__main__":
    sys.exit(main())
