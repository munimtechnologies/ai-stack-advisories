# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# Ranges holding several release lines in one string, and comparators separated only by a space
# (check_freshness.parse_ranges). The ranges below are copied from n8n advisories of 2025-2026.
import unittest

import check_freshness as cf


class ParseRangesTest(unittest.TestCase):
    def test_n8n_three_release_lines(self):
        # GHSA-mmgg-m5j7-f83h
        self.assertEqual(cf.parse_ranges("< 1.123.22, >= 2.0.0 < 2.9.3, >= 2.10.0 < 2.10.1"),
                         [(None, "1.123.22", False), ("2.0.0", "2.9.3", False), ("2.10.0", "2.10.1", False)])

    def test_strict_lower_bound_starts_a_line(self):
        # GHSA-hv53-3329-vmrm
        self.assertEqual(cf.parse_ranges("< 1.118.0, > 2.0.0 < 2.4.0"),
                         [(None, "1.118.0", False), ("2.0.0", "2.4.0", False)])

    def test_space_without_comma(self):
        self.assertEqual(cf.parse_ranges(">= 0.187.0 <1.120.3"), [("0.187.0", "1.120.3", False)])
        self.assertEqual(cf.parse_ranges(">=1.0.0 <2.0.0"), [("1.0.0", "2.0.0", False)])
        self.assertEqual(cf.parse_ranges(">= 1.0.0 <= 1.2.0"), [("1.0.0", "1.2.0", True)])

    def test_exact_versions(self):
        self.assertEqual(cf.parse_ranges("= 1.2.3"), [("1.2.3", "1.2.3", True)])
        self.assertEqual(cf.parse_ranges("< 1.0.0, = 1.5.0"), [(None, "1.0.0", False), ("1.5.0", "1.5.0", True)])

    def test_free_text_and_typos_stay_unparsed(self):
        for text in (None, "", "latest", "<= latest", "<= flowise@3.0.7 Latest", "< =3.0.12",
                     "cloud-hosted (as of July 2025)", ">= 1.0 >= 2.0", "< 1.0 < 2.0", ">= 1.0 = 2.0"):
            self.assertIsNone(cf.parse_ranges(text), text)

    def test_comparator_is_never_read_as_a_version(self):
        # v1 of parse_ranges matched the space before ">=" and took ">=" itself as the version.
        for text in ("< 1.0.0 >", "< 1.0.0, >=", ">= <1.0.0", "< 1.0.0 foo"):
            self.assertIsNone(cf.parse_ranges(text), text)
        self.assertEqual(cf._comparators("< 1.0.0, >= 2.0.0 <2.1.0"),
                         [("<", "1.0.0"), (">=", "2.0.0"), ("<", "2.1.0")])

    def test_inverted(self):
        self.assertTrue(cf._inverted(("2.0.0", "1.123.8", False)))
        self.assertFalse(cf._inverted(("1.0.0", "2.0.0", False)))
        self.assertFalse(cf._inverted((None, "2.0.0", False)))
        self.assertFalse(cf._inverted(("1.0.0", None, False)))


class AdvisoryRangesUnionTest(unittest.TestCase):
    @staticmethod
    def _adv(rng, patched=""):
        return {"vulnerabilities": [{"package": {"ecosystem": "npm", "name": "n8n"},
                                     "vulnerable_version_range": rng, "patched_versions": patched}]}

    def test_union_string_is_split(self):
        ranges = cf.advisory_ranges(self._adv("< 1.123.8, >= 2.0.0 < 2.2.0", "1.123.8, 2.2.0"), "n8n")
        self.assertEqual(ranges, [(None, "1.123.8", False), ("2.0.0", "2.2.0", False)])

    def test_two_part_union_without_spaces_is_not_read_as_empty(self):
        # Read as AND, "< 1.123.8, >= 2.0.0" would be an empty range that every feed "flags".
        ranges = cf.advisory_ranges(self._adv("< 1.123.8, >= 2.0.0", "1.123.8, 2.2.0"), "n8n")
        self.assertEqual(ranges, [(None, "1.123.8", False), ("2.0.0", None, False)])

    def test_and_ranges_unchanged(self):
        self.assertEqual(cf.advisory_ranges(self._adv(">= 1.0.0, < 1.5.0"), "n8n"), [("1.0.0", "1.5.0", False)])
        self.assertEqual(cf.advisory_ranges(self._adv("< 1.5.0, >= 1.0.0"), "n8n"), [("1.0.0", "1.5.0", False)])

    def test_single_patched_version_still_closes_the_last_line(self):
        ranges = cf.advisory_ranges(self._adv(">= 0.150.0 <2.2.2"), "n8n")
        self.assertEqual(ranges, [("0.150.0", "2.2.2", False)])
        ranges = cf.advisory_ranges(self._adv("> 0.0.1", "1.123.89"), "n8n")
        self.assertEqual(ranges, [("0.0.1", "1.123.89", False)])

    def test_gap_found_per_line(self):
        items = [{"introduced": None, "fixed": "1.123.22"}, {"introduced": "2.0.0", "fixed": "2.9.3"}]
        ranges = cf.advisory_ranges(self._adv("< 1.123.22, >= 2.0.0 < 2.9.3, >= 2.10.0 < 2.10.1"), "n8n")
        gaps = [cf.first_gap(items, *r) for r in ranges]
        self.assertEqual(gaps, [None, None, "2.10.0"])

    def test_free_text_still_unparsed(self):
        self.assertIsNone(cf.advisory_ranges(self._adv("all versions before the fix"), "n8n"))


if __name__ == "__main__":
    unittest.main()
