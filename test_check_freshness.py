"""Offline tests for check_freshness.py (no network)."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_freshness as cf  # noqa: E402

N8N_ITEMS = [
    {"introduced": None, "fixed": "1.123.83", "kind": "server", "ids": ["GHSA-x8wx-g24x-3549"]},
    {"introduced": "2.0.0", "fixed": "2.41.4", "kind": "server", "ids": ["GHSA-x8wx-g24x-3549"]},
    {"introduced": "2.42.0", "fixed": "2.42.1", "kind": "server", "ids": ["GHSA-x8wx-g24x-3549"]},
]


def vuln(name, rng):
    return {"package": {"ecosystem": "npm", "name": name}, "vulnerable_version_range": rng}


def advisory(ghsa, cve, *vulns, severity="medium"):
    return {"ghsa_id": ghsa, "cve_id": cve, "severity": severity,
            "published_at": "2026-09-30T08:38:07Z", "summary": "s",
            "html_url": "https://github.com/x/y/security/advisories/" + ghsa,
            "vulnerabilities": list(vulns)}


class VersionKeyTest(unittest.TestCase):
    def test_order(self):
        k = cf.version_key
        self.assertLess(k("1.104.0rc1"), k("1.104.0"))
        self.assertLess(k("1.104.0rc1"), k("1.104.0rc2"))
        self.assertLess(k("1.104.0"), k("1.104.1"))
        self.assertLess(k("0.29.9"), k("0.30.0"))
        self.assertLess(k("1.9.0"), k("1.10.0"))
        self.assertLess(k("1.123.83"), k("2.0.0"))

    def test_equal_forms(self):
        k = cf.version_key
        self.assertEqual(k("v0.24.0"), k("0.24.0"))
        self.assertEqual(k("1.82.0-stable"), k("1.82.0"))
        self.assertEqual(k("2.0.0"), k("2.0"))


class ParseRangeTest(unittest.TestCase):
    def test_forms(self):
        p = cf.parse_range
        self.assertEqual(p(">= 0.20.0, < 0.30.0"), ("0.20.0", "0.30.0", False))
        self.assertEqual(p("<= 3.1.4"), (None, "3.1.4", True))
        self.assertEqual(p("< 1.82.0-stable"), (None, "1.82.0-stable", False))
        self.assertEqual(p("0.6.7"), ("0.6.7", "0.6.7", True))
        self.assertEqual(p(">=0.25.2, <=0.27.2"), ("0.25.2", "0.27.2", True))

    def test_free_text_is_not_parsed(self):
        self.assertIsNone(cf.parse_range("all versions carrying the GHSA-p5rf-8p88-979c fix"))
        self.assertIsNone(cf.parse_range("v0.22.0-31-g13e212c8 (and possibly earlier versions)"))
        self.assertIsNone(cf.parse_range(""))
        self.assertIsNone(cf.parse_range(None))


class AdvisoryRangesTest(unittest.TestCase):
    def test_per_release_line(self):
        adv = advisory("GHSA-3p2g-2wpm-8h3g", None, vuln("n8n", "< 1.123.83"),
                       vuln("n8n", "< 2.42.1"), vuln("n8n", "< 2.41.4"))
        self.assertEqual(cf.advisory_ranges(adv, "n8n"), [
            (None, "1.123.83", False), ("2.41.0", "2.41.4", False), ("2.42.0", "2.42.1", False)])

    def test_own_package_only(self):
        adv = advisory("GHSA-gh98-4phw-6fmw", None, vuln("langflow", ">= 1.0.0, < 1.10.1"),
                       vuln("langflow-base", "< 0.10.1"))
        self.assertEqual(cf.advisory_ranges(adv, "langflow"), [("1.0.0", "1.10.1", False)])

    def test_unparsed(self):
        adv = advisory("GHSA-r872-gr59-vf5w", "CVE-2026-55611",
                       vuln("", "all versions carrying the GHSA-p5rf-8p88-979c fix through the current main"))
        self.assertIsNone(cf.advisory_ranges(adv, "anythingllm"))

    def test_no_ranges(self):
        self.assertIsNone(cf.advisory_ranges(advisory("GHSA-aaaa-bbbb-cccc", None), "vllm"))


class FirstGapTest(unittest.TestCase):
    def test_n8n_lines_all_flagged(self):
        for lo, hi in ((None, "1.123.83"), ("2.41.0", "2.41.4"), ("2.42.0", "2.42.1")):
            self.assertIsNone(cf.first_gap(N8N_ITEMS, lo, hi, False))

    def test_n8n_literal_range_gap(self):
        self.assertEqual(cf.first_gap(N8N_ITEMS, None, "2.41.4", False), "1.123.83")

    def test_empty_range(self):
        self.assertIsNone(cf.first_gap(N8N_ITEMS, "2.42.0", "2.42.0", False))

    def test_union_any_order(self):
        items = [{"introduced": "0.20.0", "fixed": "0.31.0"}, {"introduced": None, "fixed": "0.24.0"}]
        self.assertIsNone(cf.first_gap(items, None, "0.31.0", False))
        self.assertEqual(cf.first_gap(items, None, "0.32.0", False), "0.31.0")

    def test_mcp_inspector_gap(self):
        items = [{"introduced": None, "fixed": "0.14.1"}]
        self.assertEqual(cf.first_gap(items, None, "0.16.6", False), "0.14.1")

    def test_exact_version(self):
        items = [{"introduced": None, "fixed": "1.9.0"}]
        self.assertIsNone(cf.first_gap(items, "0.6.7", "0.6.7", True))

    def test_last_affected(self):
        items = [{"introduced": "0.25.2", "fixed": None, "lastAffected": "0.27.2"}]
        self.assertIsNone(cf.first_gap(items, "0.25.2", "0.27.2", True))
        self.assertEqual(cf.first_gap(items, "0.25.2", "0.27.3", False), "0.27.2")

    def test_unbounded_needs_open_entry(self):
        self.assertEqual(cf.first_gap([{"introduced": None, "fixed": "1.16.2"}], "1.11.2", None, False), "1.16.2")
        self.assertIsNone(cf.first_gap([{"introduced": "1.0.0", "fixed": None}], "1.11.2", None, False))

    def test_only_entries_ignored(self):
        items = [{"introduced": "1.82.7", "fixed": None, "only": ["1.82.7", "1.82.8"]}]
        self.assertEqual(cf.first_gap(items, "1.82.7", "1.82.7", True), "1.82.7")

    def test_nothing_flagged(self):
        self.assertEqual(cf.first_gap([], None, "1.0.0", False), "the first version")


FEED = {
    "checked": "2026-10-11",
    "about": "test",
    "products": {
        "n8n": {"name": "n8n", "items": N8N_ITEMS},
        "mcpinspector": {"name": "MCP Inspector", "items": [
            {"introduced": None, "fixed": "0.14.1", "kind": "server", "ids": ["CVE-2025-49596"],
             "url": "https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g"}]},
    },
}

ADVISORIES = {
    "n8n-io/n8n": [
        advisory("GHSA-x8wx-g24x-3549", None, vuln("n8n", "< 1.123.83")),
        advisory("GHSA-3p2g-2wpm-8h3g", None, vuln("n8n", "< 1.123.83"),
                 vuln("n8n", "< 2.42.1"), vuln("n8n", "< 2.41.4")),
        advisory("GHSA-2r5r-xgvc-rj4p", None, vuln("n8n", "< 2.42.1"), vuln("n8n", "< 2.41.4")),
        advisory("GHSA-p3pg-xw4f-m72c", None, vuln("n8n", "< 2.42.0"), vuln("n8n", "< 2.41.4")),
    ],
    "modelcontextprotocol/inspector": [
        advisory("GHSA-g9hg-qhmf-q45m", "CVE-2025-58444",
                 vuln("@modelcontextprotocol/inspector", "< 0.16.6"), severity="high"),
        advisory("GHSA-7f8r-222p-6f5g", "CVE-2025-49596",
                 vuln("@modelcontextprotocol/inspector", "< 0.14.1"), severity="critical"),
    ],
}


def fake_fetch(repo):
    return ADVISORIES.get(repo, [])


class RunTest(unittest.TestCase):
    def test_report(self):
        pending = json.dumps({"products": {"n8n": {"items": [{"ids": ["ghsa-p3pg-xw4f-m72c"]}]}}})
        report = cf.run(json.dumps(FEED), pending, fake_fetch)
        by_id = {row["ids"][0]: row for row in report}
        self.assertEqual(sorted(by_id), ["GHSA-2r5r-xgvc-rj4p", "GHSA-3p2g-2wpm-8h3g", "GHSA-g9hg-qhmf-q45m"])
        self.assertEqual(by_id["GHSA-3p2g-2wpm-8h3g"]["status"], "range already flagged")
        self.assertEqual(by_id["GHSA-2r5r-xgvc-rj4p"]["status"], "not flagged")
        self.assertEqual(by_id["GHSA-2r5r-xgvc-rj4p"]["notFlaggedFrom"], "1.123.83")
        self.assertEqual(by_id["GHSA-g9hg-qhmf-q45m"]["notFlaggedFrom"], "0.14.1")
        self.assertEqual(by_id["GHSA-g9hg-qhmf-q45m"]["severity"], "HIGH")

    def test_app_filter(self):
        report = cf.run(json.dumps(FEED), "", fake_fetch, apps=["mcpinspector"])
        self.assertEqual([row["app"] for row in report], ["mcpinspector"])

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = os.path.join(tmp, "advisories.json")
            with open(feed, "w", encoding="utf-8") as handle:
                json.dump(FEED, handle)
            original = cf.fetch_advisories
            cf.fetch_advisories = lambda repo, token=None: fake_fetch(repo)
            try:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cf.main(["--feed", feed, "--pending", os.path.join(tmp, "none.json"), "--json"])
                self.assertEqual(code, 1)
                self.assertEqual(len(json.loads(out.getvalue())), 4)

                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cf.main(["--feed", feed, "--app", "ollama"])
                self.assertEqual(code, 0)
                self.assertIn("No published advisories missing.", out.getvalue())
            finally:
                cf.fetch_advisories = original


class PendingFileTest(unittest.TestCase):
    """pending-advisories.json must stay in advisories.json's entry format."""

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pending-advisories.json")

    def test_format(self):
        if not os.path.exists(self.path):
            self.skipTest("no pending-advisories.json")
        with open(self.path, encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertIn("checked", data)
        allowed = {"introduced", "fixed", "lastAffected", "only", "kind", "ids", "severity",
                   "inPublicDatabases", "summary", "url"}
        for app, product in data["products"].items():
            self.assertIn(app, cf.PROJECTS)
            self.assertTrue(product["name"])
            for item in product["items"]:
                self.assertLessEqual(set(item), allowed)
                self.assertIn(item["kind"], ("server", "feature", "windows"))
                self.assertIn(item["severity"], ("CRITICAL", "HIGH", "MODERATE", "LOW", None))
                self.assertTrue(item["ids"])
                for advisory_id in item["ids"]:
                    self.assertRegex(advisory_id, r"^(GHSA(-[0-9a-z]{4}){3}|CVE-\d{4}-\d{4,})$")
                self.assertTrue(item["url"].startswith("https://"))
                if item.get("introduced") and item.get("fixed"):
                    self.assertLess(cf.version_key(item["introduced"]), cf.version_key(item["fixed"]))


if __name__ == "__main__":
    unittest.main()
