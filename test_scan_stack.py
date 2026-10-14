"""Unit tests for scan_stack (the GitHub Action / CLI repo scanner).

Run from this folder with `python -m unittest -v`, or from anywhere with
`python path/to/test_scan_stack.py -v`. The tests use a small fixture, so they don't depend on
the current contents of advisories.json; the RealDataTests check that file only if it is present.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan_stack as ss  # noqa: E402

FIXTURE = {
    "checked": "2026-10-12",
    "products": {
        "ollama": {"name": "Ollama", "items": [
            {"introduced": "0.34.2", "fixed": "0.35.0", "kind": "server", "ids": ["CVE-2026-103663"],
             "severity": None, "summary": "Path traversal in /api/pull.", "url": "https://example.org/a"},
            {"introduced": "0.12.10", "fixed": "0.24.0", "kind": "windows", "ids": ["CVE-2026-42248"],
             "severity": None, "summary": "Windows updater.", "url": "https://example.org/b"},
        ]},
        "openwebui": {"name": "Open WebUI", "items": [
            {"introduced": "0.7.0", "fixed": "0.11.4", "kind": "server", "ids": ["GHSA-vpq8-f445-hcq7"],
             "severity": "HIGH", "inPublicDatabases": False, "summary": "Token theft.", "url": "https://example.org/c"},
        ]},
        "n8n": {"name": "n8n", "items": [
            {"introduced": "2.0.0", "fixed": "2.41.4", "kind": "server", "ids": ["GHSA-x5cw-hm7v-q7mj"],
             "severity": "HIGH", "inPublicDatabases": False, "summary": "Stored XSS.", "url": "https://example.org/d"},
            {"introduced": "2.42.0", "fixed": "2.42.1", "kind": "server", "ids": ["GHSA-4c7j-qff5-r9cx"],
             "severity": "MODERATE", "summary": "Beta line.", "url": "https://example.org/e"},
        ]},
        "flowise": {"name": "Flowise", "items": [
            {"introduced": None, "fixed": None, "lastAffected": "3.1.4", "kind": "server", "ids": ["GHSA-cffm-583c-vffr"],
             "severity": "CRITICAL", "summary": "SSO takeover.", "url": "https://example.org/f"},
        ]},
        "litellm": {"name": "LiteLLM", "items": [
            {"introduced": None, "fixed": "1.95.0", "kind": "server", "ids": ["GHSA-g5ff-637f-6q2m"],
             "severity": "HIGH", "summary": "File read.", "url": "https://example.org/g"},
        ]},
        "vllm": {"name": "vLLM", "items": [
            {"introduced": "0.6.5", "fixed": "0.8.5", "kind": "feature", "ids": ["CVE-2025-47277"],
             "severity": "CRITICAL", "summary": "KV transfer only.", "url": "https://example.org/h"},
        ]},
    },
}

COMPOSE = """services:
  ollama:
    image: ollama/ollama:0.34.5
  open-webui:
    image: "ghcr.io/open-webui/open-webui:main"
  n8n:
    image: docker.n8n.io/n8nio/n8n:2.41.4
  old-ollama:
    image: ollama/ollama:${OLLAMA_TAG:-0.34.2}
  unrelated:
    image: postgres:16
"""


def write(folder, name, text):
    p = Path(folder) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class ParseTests(unittest.TestCase):
    def test_parse_image(self):
        self.assertEqual(ss.parse_image("ghcr.io/open-webui/open-webui:v0.11.2"), ("open-webui/open-webui", "v0.11.2"))
        self.assertEqual(ss.parse_image("docker.n8n.io/n8nio/n8n:2.40.0"), ("n8nio/n8n", "2.40.0"))
        self.assertEqual(ss.parse_image("ollama/ollama"), ("ollama/ollama", None))
        self.assertEqual(ss.parse_image("localhost:5000/ollama/ollama:0.34.5@sha256:abc"), ("ollama/ollama", "0.34.5"))
        self.assertEqual(ss.parse_image("ollama/ollama:${TAG:-0.30.1}"), ("ollama/ollama", "0.30.1"))
        self.assertEqual(ss.parse_image("${REG:-docker.io}/ollama/ollama:0.1.0"), ("ollama/ollama", "0.1.0"))

    def test_tag_version(self):
        self.assertEqual(ss.tag_version("main-v1.74.0-stable"), "1.74.0")
        self.assertEqual(ss.tag_version("v0.20.0-slim"), "0.20.0")
        self.assertEqual(ss.tag_version("0.12.3-rocm"), "0.12.3")
        self.assertIsNone(ss.tag_version("latest"))
        self.assertIsNone(ss.tag_version("cuda"))
        self.assertIsNone(ss.tag_version(None))
        self.assertIsNone(ss.tag_version("${TAG}"))

    def test_file_kind(self):
        self.assertEqual(ss.file_kind(Path("docker-compose.yml")), "yaml")
        self.assertEqual(ss.file_kind(Path("k8s/ollama.yaml")), "yaml")
        self.assertEqual(ss.file_kind(Path("Dockerfile")), "docker")
        self.assertEqual(ss.file_kind(Path("Dockerfile.gpu")), "docker")
        self.assertEqual(ss.file_kind(Path("requirements-dev.txt")), "req")
        self.assertEqual(ss.file_kind(Path("package.json")), "npm")
        self.assertIsNone(ss.file_kind(Path("README.md")))


class AffectingTests(unittest.TestCase):
    def test_ranges(self):
        items = FIXTURE["products"]["n8n"]["items"]
        self.assertEqual([h["ids"][0] for h in ss.affecting(items, "2.40.0")], ["GHSA-x5cw-hm7v-q7mj"])
        self.assertEqual(ss.affecting(items, "2.41.4"), [])
        self.assertEqual([h["ids"][0] for h in ss.affecting(items, "2.42.0")], ["GHSA-4c7j-qff5-r9cx"])
        self.assertEqual(ss.affecting(items, "1.9.0"), [])

    def test_no_fix_uses_last_affected(self):
        items = FIXTURE["products"]["flowise"]["items"]
        self.assertEqual(len(ss.affecting(items, "3.1.4")), 1)
        self.assertEqual(ss.affecting(items, "3.1.5"), [])

    def test_windows_skipped_for_images(self):
        items = FIXTURE["products"]["ollama"]["items"]
        self.assertEqual(len(ss.affecting(items, "0.20.0")), 1)
        self.assertEqual(ss.affecting(items, "0.20.0", skip_windows=True), [])


class ScanTests(unittest.TestCase):
    def test_compose(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "docker-compose.yml", COMPOSE)
            found = ss.scan_paths([d], FIXTURE)
        by_line = {f["line"]: f for f in found}
        self.assertEqual(sorted(by_line), [3, 5, 7, 9])
        self.assertEqual(by_line[3]["status"], "affected")
        self.assertEqual(by_line[3]["upgradeTo"], "0.35.0")
        self.assertEqual(by_line[5]["status"], "unpinned")
        self.assertEqual(by_line[7]["status"], "ok")
        self.assertEqual(by_line[9]["version"], "0.34.2")
        self.assertEqual(by_line[9]["status"], "affected")

    def test_windows_only_image_is_ok(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "compose.yaml", "services:\n  o:\n    image: ollama/ollama:0.20.0\n")
            found = ss.scan_paths([d], FIXTURE)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["status"], "ok")

    def test_dockerfile_no_fix(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "app/Dockerfile", "ARG X=1\nFROM --platform=linux/amd64 flowiseai/flowise:3.1.4 AS app\n")
            found = ss.scan_paths([d], FIXTURE)
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertEqual((f["line"], f["status"], f["upgradeTo"], f["noFixedRelease"]), (2, "affected", None, 1))
        self.assertIn("no fixed release yet", ss.describe(f))

    def test_requirements(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt", "# pins\nlitellm[proxy]==1.82.7\nopen_webui==0.11.4\nrequests==2.31.0\n")
            found = ss.scan_paths([d], FIXTURE)
        self.assertEqual([(f["product"], f["status"]) for f in found], [("litellm", "affected"), ("openwebui", "ok")])
        self.assertEqual(found[0]["upgradeTo"], "1.95.0")

    def test_package_json_range(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps({"name": "x", "dependencies": {"n8n": "^2.40.0", "left-pad": "1.0.0"}}, indent=2))
            found = ss.scan_paths([d], FIXTURE)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["range"])
        self.assertEqual(found[0]["status"], "affected")
        self.assertIn("lowest version", ss.describe(found[0]))

    def test_feature_flag_and_skip_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt", "vllm==0.7.0\n")
            write(d, "node_modules/x/compose.yml", "services:\n  o:\n    image: ollama/ollama:0.34.5\n")
            found = ss.scan_paths([d], FIXTURE)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["advisories"][0]["onlyIfFeatureUsed"])


class OutputTests(unittest.TestCase):
    def run_main(self, folder, *extra):
        with tempfile.TemporaryDirectory() as d2:
            adv = write(d2, "advisories.json", json.dumps(FIXTURE))
            buf = io.StringIO()
            old = os.environ.pop("GITHUB_ACTIONS", None)
            try:
                with redirect_stdout(buf):
                    code = ss.main([folder, "--advisories", str(adv), *extra])
            finally:
                if old is not None:
                    os.environ["GITHUB_ACTIONS"] = old
        return code, buf.getvalue()

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "docker-compose.yml", COMPOSE)
            code, out = self.run_main(d)
            self.assertEqual(code, 1)
            self.assertIn("CVE-2026-103663", out)
            self.assertIn("by MV2 of Munim, Inc., https://github.com/munimv2/ai-stack-advisories", out)
            self.assertNotIn("an AI", out)
            code, _ = self.run_main(d, "--fail-on", "never")
            self.assertEqual(code, 0)
            code, out = self.run_main(d, "--json")
            self.assertEqual(json.loads(out)["curatedDataAsOf"], "2026-10-12")

    def test_clean_repo(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "compose.yml", "services:\n  db:\n    image: postgres:16\n")
            code, out = self.run_main(d)
        self.assertEqual(code, 0)
        self.assertIn("Checked 0 pinned", out)

    def test_annotations_escape(self):
        f = {"file": "a,b:c.yml", "line": 3, "name": "Ollama", "version": "0.34.5", "ref": "ollama/ollama:0.34.5",
             "status": "affected", "advisories": [{}], "upgradeTo": "0.35.0", "noFixedRelease": 0, "range": False}
        (line,) = ss.annotations([f])
        self.assertTrue(line.startswith("::error file=a%2Cb%3Ac.yml,line=3,title=Ollama 0.34.5::"))

    def test_step_summary(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "docker-compose.yml", COMPOSE)
            found = ss.scan_paths([d], FIXTURE)
        md = ss.step_summary(found, FIXTURE)
        self.assertIn("| Ollama 0.34.5 | affected (1) | 0.35.0 |", md)
        self.assertIn("Open WebUI (unpinned)", md)
        self.assertIn("Made by MV2 of Munim, Inc.:", md)


class RealDataTests(unittest.TestCase):
    def load(self):
        path = Path(ss.HERE) / "advisories.json"
        if not path.exists():
            self.skipTest("advisories.json not next to scan_stack.py")
        return json.loads(path.read_text(encoding="utf-8"))

    def ids_at(self, data, key, version):
        return {i for item in ss.affecting(data["products"][key]["items"], version) for i in item["ids"]}

    def test_bundled_advisories_cover_every_mapping(self):
        data = self.load()
        keys = set(ss.IMAGES.values()) | set(ss.PYPI.values()) | set(ss.NPM.values())
        self.assertFalse(keys - set(data["products"]), "mapped products missing from advisories.json")
        for key in keys:
            for item in data["products"][key]["items"]:
                self.assertTrue(item["ids"] and item["url"] and item["summary"])
                ss.affecting([item], "0.0.1")

    def test_entry_format(self):
        data = self.load()
        allowed = {"introduced", "fixed", "lastAffected", "only", "kind", "ids", "severity",
                   "inPublicDatabases", "summary", "url"}
        for key, product in data["products"].items():
            self.assertTrue(product["name"], key)
            for item in product["items"]:
                self.assertLessEqual(set(item), allowed, item["ids"])
                self.assertIn(item["kind"], ("server", "feature", "windows"))
                self.assertIn(item["severity"], ("CRITICAL", "HIGH", "MODERATE", "LOW", None))
                if item.get("introduced") and item.get("fixed"):
                    self.assertLess(ss.vtuple(item["introduced"]), ss.vtuple(item["fixed"]), item["ids"])

    def test_version_gaps_closed_on_2026_10_14(self):
        # Versions the 2026-10-14 sweep found unflagged, now covered by the merged entries.
        data = self.load()
        self.assertIn("GHSA-g9hg-qhmf-q45m", self.ids_at(data, "mcpinspector", "0.15.0"))
        self.assertNotIn("GHSA-g9hg-qhmf-q45m", self.ids_at(data, "mcpinspector", "0.16.6"))
        self.assertIn("GHSA-r872-gr59-vf5w", self.ids_at(data, "anythingllm", "1.16.2"))
        self.assertIn("GHSA-p3pg-xw4f-m72c", self.ids_at(data, "n8n", "1.123.83"))
        self.assertIn("CVE-2026-108836", self.ids_at(data, "ollama", "0.34.1"))
        self.assertNotIn("CVE-2026-108836", self.ids_at(data, "ollama", "0.34.2"))
        self.assertNotIn("an AI", data["about"])


if __name__ == "__main__":
    unittest.main()
