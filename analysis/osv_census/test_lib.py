# SPDX-License-Identifier: Apache-2.0
# Part of ai-stack-advisories by MV2, Munim, Inc. Made with AI.
"""Offline unit tests for the pure census logic (stdlib only, no network)."""
import unittest

import lib


class TestParsing(unittest.TestCase):
    def test_parse_advisory_extracts_fields(self):
        adv = {
            "ghsa_id": "GHSA-vpq8-f445-hcq7",
            "cve_id": None,
            "severity": "High",
            "published_at": "2026-09-27T19:47:06Z",
            "withdrawn_at": None,
            "vulnerabilities": [
                {"first_patched_version": {"identifier": "0.11.4"}},
            ],
        }
        p = lib.parse_advisory(adv)
        self.assertEqual(p["ghsa_id"], "GHSA-vpq8-f445-hcq7")
        self.assertEqual(p["severity"], "high")
        self.assertTrue(p["has_fix"])
        self.assertEqual(p["first_patched_version"], "0.11.4")

    def test_parse_advisory_no_fix(self):
        adv = {
            "ghsa_id": "GHSA-xxxx",
            "severity": "critical",
            "published_at": "2026-09-10T00:00:00Z",
            "vulnerabilities": [{"first_patched_version": None}],
        }
        p = lib.parse_advisory(adv)
        self.assertFalse(p["has_fix"])
        self.assertIsNone(p["first_patched_version"])

    def test_days_between(self):
        self.assertEqual(
            lib.days_between("2026-09-27T00:00:00Z", "2026-10-17T00:00:00Z"), 20
        )
        self.assertEqual(
            lib.days_between("2026-10-17T00:00:00Z", "2026-09-27T00:00:00Z"), 0
        )


class TestSummarize(unittest.TestCase):
    def setUp(self):
        self.records = [
            {"ghsa_id": "A", "severity": "high", "published_at": "2026-09-27T00:00:00Z", "osv_present": False},
            {"ghsa_id": "B", "severity": "medium", "published_at": "2026-10-01T00:00:00Z", "osv_present": True},
            {"ghsa_id": "C", "severity": "medium", "published_at": "2026-05-10T00:00:00Z", "osv_present": False},
            {"ghsa_id": "D", "severity": "high", "published_at": "2026-01-01T00:00:00Z", "osv_present": True, "withdrawn_at": "2026-02-01T00:00:00Z"},
        ]

    def test_counts_exclude_withdrawn(self):
        s = lib.summarize(self.records, "2026-10-17T00:00:00Z")
        self.assertEqual(s["total_active_advisories"], 3)
        self.assertEqual(s["in_osv"], 1)
        self.assertEqual(s["absent_from_osv"], 2)
        self.assertEqual(s["osv_coverage_pct"], 33.3)

    def test_oldest_absent(self):
        s = lib.summarize(self.records, "2026-10-17T00:00:00Z")
        self.assertEqual(s["oldest_absent"]["ghsa_id"], "C")

    def test_absent_list_sorted_oldest_first(self):
        s = lib.summarize(self.records, "2026-10-17T00:00:00Z")
        ids = [x["ghsa_id"] for x in s["absent_list"]]
        self.assertEqual(ids, ["C", "A"])


class TestLedger(unittest.TestCase):
    def test_new_absent_then_appears(self):
        recs1 = [{"ghsa_id": "A", "severity": "high", "published_at": "2026-09-27T00:00:00Z", "osv_present": False}]
        led = lib.merge_ledger({}, recs1, "2026-10-01T00:00:00Z")
        self.assertIsNone(led["A"]["osv_first_seen"])
        self.assertFalse(led["A"]["osv_present"])

        recs2 = [{"ghsa_id": "A", "severity": "high", "published_at": "2026-09-27T00:00:00Z", "osv_present": True}]
        led = lib.merge_ledger(led, recs2, "2026-10-10T00:00:00Z")
        self.assertEqual(led["A"]["osv_first_seen"], "2026-10-10T00:00:00Z")
        self.assertTrue(led["A"]["osv_present"])

    def test_latency_only_counts_witnessed(self):
        led = {
            # witnessed: absent at first_checked, appeared later -> latency defined
            "A": {"ghsa_id": "A", "published_at": "2026-09-27T00:00:00Z",
                  "first_checked": "2026-10-01T00:00:00Z", "osv_present": True,
                  "osv_first_seen": "2026-10-10T00:00:00Z"},
            # already present at first sight -> not a measured latency (censored)
            "B": {"ghsa_id": "B", "published_at": "2026-09-01T00:00:00Z",
                  "first_checked": "2026-10-01T00:00:00Z", "osv_present": True,
                  "osv_first_seen": "2026-10-01T00:00:00Z"},
            "C": {"ghsa_id": "C", "published_at": "2026-05-10T00:00:00Z",
                  "first_checked": "2026-10-01T00:00:00Z", "osv_present": False,
                  "osv_first_seen": None},
        }
        stats = lib.ledger_latency_stats(led)
        self.assertEqual(stats["witnessed_ingestions"], 1)
        self.assertEqual(stats["median_latency_days"], 13)
        self.assertEqual(stats["still_absent"], 1)
        self.assertEqual(stats["total_tracked"], 3)

    def test_merge_does_not_mutate_input(self):
        original = {}
        recs = [{"ghsa_id": "A", "severity": "low", "published_at": "2026-09-27T00:00:00Z", "osv_present": False}]
        lib.merge_ledger(original, recs, "2026-10-01T00:00:00Z")
        self.assertEqual(original, {})


if __name__ == "__main__":
    unittest.main()
