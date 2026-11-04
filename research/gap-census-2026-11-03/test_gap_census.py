# Apache-2.0. MV2 of Munim, Inc. (made with AI agents). Offline tests for gap_census.py (v2).
# FEED_DIR must point at a clone of munimtechnologies/ai-stack-advisories (for check_freshness.py).
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.environ.get("FEED_DIR", "/tmp/feed"))

import check_freshness as cf  # noqa: E402
import gap_census as gc  # noqa: E402


def adv(rng, patched, name="vllm", eco="pip", ghsa="GHSA-aaaa-bbbb-cccc"):
    return {"ghsa_id": ghsa, "cve_id": None, "severity": "high", "published_at": "2026-10-20T00:00:00Z",
            "html_url": "https://example.invalid/" + ghsa,
            "vulnerabilities": [{"package": {"ecosystem": eco, "name": name},
                                 "vulnerable_version_range": rng, "patched_versions": patched}]}


class Bounds(unittest.TestCase):
    def test_inclusive_gap(self):
        self.assertEqual(gc.gap_bounds(cf, "<= 0.25.1", "0.32.0"), ("0.25.1", True))

    def test_exclusive_gap(self):
        self.assertEqual(gc.gap_bounds(cf, "< 0.21.0", "0.27.0"), ("0.21.0", False))

    def test_bare_version(self):
        self.assertEqual(gc.gap_bounds(cf, "0.26.0", "0.32.0"), ("0.26.0", True))

    def test_range_ending_at_patched_is_no_gap(self):
        self.assertIsNone(gc.gap_bounds(cf, "< 0.31.0", "0.31.0"))

    def test_open_ended_is_no_gap(self):
        self.assertIsNone(gc.gap_bounds(cf, ">= 0.1.0", "0.10.1.1"))

    def test_typo_and_unions_skipped(self):
        self.assertIsNone(gc.gap_bounds(cf, "< 030.0", "0.30.0"))
        self.assertIsNone(gc.gap_bounds(cf, "< 1.0.5, >= 2.0.0 < 2.0.3", "2.0.3"))

    def test_single_patched(self):
        self.assertEqual(gc.single_patched("=> 0.26.0"), "0.26.0")
        self.assertEqual(gc.single_patched(">= v0.14.1"), "0.14.1")
        self.assertIsNone(gc.single_patched("1.106.5, 1.105.6"))
        self.assertIsNone(gc.single_patched("latest"))


class Releases(unittest.TestCase):
    def test_in_gap(self):
        self.assertTrue(gc.in_gap(cf, "0.26.0", "0.25.1", True, "0.32.0"))
        self.assertFalse(gc.in_gap(cf, "0.25.1", "0.25.1", True, "0.32.0"))
        self.assertTrue(gc.in_gap(cf, "0.21.0", "0.21.0", False, "0.27.0"))
        self.assertFalse(gc.in_gap(cf, "0.32.0", "0.25.1", True, "0.32.0"))

    def test_prerelease(self):
        for v in ("1.8.0.rc1", "0.10.0rc2", "2.0.0-beta.1", "1.0.0a1", "1.0.0.dev3"):
            self.assertTrue(gc.is_prerelease(v), v)
        for v in ("0.6.0-stable", "1.10.1-fix.1", "1.2.3", "v0.14.1", "1.0.0.post1"):
            self.assertFalse(gc.is_prerelease(v), v)

    def test_parse_ls_remote(self):
        text = ("abc\trefs/tags/v0.12.4\nabd\trefs/tags/v0.12.4^{}\nabe\trefs/tags/0.13.0\n"
                "abf\trefs/tags/nightly\nabg\trefs/heads/main\nbad line\n")
        self.assertEqual(gc.parse_ls_remote(text), ["0.12.4", "0.13.0"])

    def test_default_package_when_advisory_name_blank(self):
        calls = []

        def fake_registry(eco, name):
            calls.append((eco, name))
            return ("pypi:" + name, ["1.0.0", "1.1.0"]) if name == "langflow" else (None, [])
        orig = gc.registry_versions
        gc.registry_versions = fake_registry
        try:
            src, versions = gc.releases_for("", "", "langflow-ai/langflow", {}, "langflow")
        finally:
            gc.registry_versions = orig
        self.assertTrue(src.startswith("pypi:langflow (project default"))
        self.assertEqual(versions, ["1.0.0", "1.1.0"])
        self.assertEqual(calls, [("", ""), ("pip", "langflow")])

    def test_rate_limit_wait(self):
        self.assertIsNone(gc.rate_limit_wait({"X-RateLimit-Remaining": "12"}))
        self.assertIsNone(gc.rate_limit_wait(None))
        self.assertEqual(gc.rate_limit_wait({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1100"}, now=1000), 105)
        self.assertEqual(gc.rate_limit_wait({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "99999"}, now=0), 3700)
        self.assertEqual(gc.rate_limit_wait({"X-RateLimit-Remaining": "0"}), 900)


class Osv(unittest.TestCase):
    REC = {"affected": [{"package": {"ecosystem": "PyPI", "name": "vllm"},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.32.0"}]}]}]}
    LAST = {"affected": [{"package": {"ecosystem": "PyPI", "name": "vllm"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                                      {"last_affected": "0.25.1"}]}]}]}

    def test_fixed_event(self):
        self.assertTrue(gc.osv_affects(cf, self.REC, {"vllm"}, "0.31.0"))
        self.assertFalse(gc.osv_affects(cf, self.REC, {"vllm"}, "0.32.0"))

    def test_last_affected_event(self):
        self.assertTrue(gc.osv_affects(cf, self.LAST, {"vllm"}, "0.25.1"))
        self.assertFalse(gc.osv_affects(cf, self.LAST, {"vllm"}, "0.26.0"))

    def test_other_package(self):
        self.assertIsNone(gc.osv_affects(cf, self.REC, {"langflow"}, "0.26.0"))


class Census(unittest.TestCase):
    def test_counts(self):
        feed = {"products": {"vllm": {"items": [{"introduced": None, "fixed": "0.32.0"}]}}}
        advs = {"vllm-project/vllm": [adv("<= 0.25.1", "0.32.0", ghsa="GHSA-1111-1111-1111"),
                                      adv("<= 0.9.5", ">= 0.9.6", ghsa="GHSA-2222-2222-2222"),
                                      adv("< 0.31.0", "0.31.0", ghsa="GHSA-3333-3333-3333")]}
        releases = ["0.9.5", "0.9.6", "0.25.1", "0.26.0", "0.27.0rc1", "0.27.0", "0.31.0", "0.32.0"]
        rows, per_app = gc.census(cf, feed, lambda repo: advs.get(repo, []),
                                  lambda ghsa: Osv.REC if ghsa == "GHSA-1111-1111-1111" else None,
                                  lambda eco, name, repo, app=None: ("test", releases))
        s = per_app["vllm"]
        self.assertEqual((s["advisories"], s["single_range_single_patch"], s["gap"]), (3, 3, 2))
        self.assertEqual((s["gap_with_stable_release"], s["stable_releases_in_gaps"]), (1, 3))
        self.assertEqual((s["osv_marks_all"], s["feed_flags_all"]), (1, 1))
        row = [r for r in rows if r["ghsa"] == "GHSA-1111-1111-1111"][0]
        self.assertEqual(row["stable_releases_in_gap"], ["0.26.0", "0.27.0", "0.31.0"])
        self.assertEqual(row["prereleases_in_gap"], 1)

    def test_no_matching_package_counted(self):
        feed = {"products": {"vllm": {"items": [{"introduced": None, "fixed": "0.32.0"}]}}}
        advs = {"vllm-project/vllm": [adv("<= 0.25.1", "0.32.0", ghsa="GHSA-4444-4444-4444")]}
        other = {"affected": [{"package": {"ecosystem": "PyPI", "name": "vlm"}, "ranges": []}]}
        rows, per_app = gc.census(cf, feed, lambda repo: advs.get(repo, []), lambda ghsa: other,
                                  lambda eco, name, repo, app=None: ("test", ["0.26.0"]))
        self.assertEqual(per_app["vllm"]["osv_no_matching_package"], 1)
        self.assertEqual(rows[0]["osv"], "no matching package")


if __name__ == "__main__":
    unittest.main()
