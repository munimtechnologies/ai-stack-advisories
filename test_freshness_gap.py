# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# check_freshness.py reads an advisory whose single range stops below its one patched version as affected up
# to that version (vLLM's GHSA-6757-hggm-hp2w: "<= 0.25.1", patched 0.32.0), reads "=>" as ">=", and reports a
# leading-zero version ("< 030.0", vLLM's GHSA-2phq-3phc-84px) as not parsed instead of covering every release.
# Range shapes are the ones vLLM published; checked against OSV.dev's records on 2 November 2026.
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_freshness as cf  # noqa: E402


def adv(rng, patched, name="vllm", ghsa="GHSA-aaaa-bbbb-cccc"):
    return {"ghsa_id": ghsa, "cve_id": None, "severity": "medium", "published_at": "2026-10-20T00:00:00Z",
            "summary": "test", "html_url": "https://example.invalid/" + ghsa,
            "vulnerabilities": [{"package": {"ecosystem": "pip", "name": name},
                                 "vulnerable_version_range": rng, "patched_versions": patched}]}


class GapRule(unittest.TestCase):
    def test_inclusive_bound_below_patched(self):
        self.assertEqual(cf.advisory_ranges(adv("<= 0.25.1", "0.32.0"), "vllm"), [(None, "0.32.0", False)])

    def test_exclusive_bound_below_patched(self):
        self.assertEqual(cf.advisory_ranges(adv("< 0.21.0", ">= 0.27.0"), "vllm"), [(None, "0.27.0", False)])

    def test_lower_and_upper_bound_below_patched(self):
        self.assertEqual(cf.advisory_ranges(adv(">= 0.16.0, <= 0.23.0", "0.32.0"), "vllm"),
                         [("0.16.0", "0.32.0", False)])

    def test_bare_version_below_patched(self):
        self.assertEqual(cf.advisory_ranges(adv("0.26.0", "0.32.0"), "vllm"), [("0.26.0", "0.32.0", False)])

    def test_reversed_operator_in_patched(self):
        self.assertEqual(cf.advisory_ranges(adv("<= 0.24.0", "=> 0.26.0"), "vllm"), [(None, "0.26.0", False)])

    def test_range_ending_at_patched_is_unchanged(self):
        self.assertEqual(cf.advisory_ranges(adv("< 0.31.0", "0.31.0"), "vllm"), [(None, "0.31.0", False)])

    def test_open_ended_range_still_ends_at_patched(self):
        self.assertEqual(cf.advisory_ranges(adv(">= 0.1.0", "0.10.1.1"), "vllm"), [("0.1.0", "0.10.1.1", False)])

    def test_several_patched_versions_are_left_alone(self):
        self.assertEqual(cf.advisory_ranges(adv("< 1.103.10", "1.106.5, 1.105.6, 1.104.8, 1.103.10",
                                                name="litellm"), "litellm"),
                         [(None, "1.103.10", False)])

    def test_release_lines_in_one_string_are_not_extended(self):
        self.assertEqual(cf.advisory_ranges(adv("< 1.0.5, >= 2.0.0 < 2.0.3", "2.0.3", name="n8n"), "n8n"),
                         [(None, "1.0.5", False), ("2.0.0", "2.0.3", False)])


class LeadingZero(unittest.TestCase):
    def test_leading_zero_range_is_not_parsed(self):
        self.assertIsNone(cf.advisory_ranges(adv("< 030.0", ">= 0.30.0"), "vllm"))

    def test_plain_zero_components_still_parse(self):
        self.assertEqual(cf.advisory_ranges(adv("< 0.0.10", "0.0.10"), "vllm"), [(None, "0.0.10", False)])


class Report(unittest.TestCase):
    def test_gap_range_is_reported_not_flagged(self):
        items = [{"introduced": None, "fixed": "0.25.0", "kind": "server", "ids": ["CVE-2000-0001"]}]
        rows = cf.check_app("vllm", items, [adv("<= 0.24.0", "=> 0.26.0")], set())
        self.assertEqual([(r["status"], r["notFlaggedFrom"]) for r in rows], [("not flagged", "0.25.0")])

    def test_typo_range_is_reported_not_parsed(self):
        items = [{"introduced": None, "fixed": "0.30.0", "kind": "server", "ids": ["CVE-2000-0002"]}]
        rows = cf.check_app("vllm", items, [adv("< 030.0", ">= 0.30.0")], set())
        self.assertEqual([r["status"] for r in rows], ["range not parsed"])


if __name__ == "__main__":
    unittest.main()
