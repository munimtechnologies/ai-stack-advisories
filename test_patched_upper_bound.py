# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# Open-ended advisory ranges that name a single patched version (check_freshness._with_patched).
import unittest

import check_freshness as cf


class PatchedUpperBoundTest(unittest.TestCase):
    def test_open_range_ends_at_single_patched_version(self):
        # vLLM GHSA-rxc4-3w6r-4v47: range ">=0.1.0", patched "0.10.1.1".
        self.assertEqual(cf._with_patched(("0.1.0", None, False), {"patched_versions": "0.10.1.1"}),
                         ("0.1.0", "0.10.1.1", False))

    def test_ge_prefix_and_v_prefix(self):
        self.assertEqual(cf._with_patched(("0.5.5", None, False), {"patched_versions": ">= 0.11.0"}),
                         ("0.5.5", "0.11.0", False))
        self.assertEqual(cf._with_patched(("1.2.1", None, False), {"patched_versions": "v2.0.0"}),
                         ("1.2.1", "2.0.0", False))

    def test_several_patched_versions_stay_open(self):
        rng = ("1.36.0", None, False)
        self.assertEqual(cf._with_patched(rng, {"patched_versions": "1.123.89, 2.45.5"}), rng)

    def test_bounded_or_unparsed_ranges_unchanged(self):
        rng = ("0.1.0", "0.2.0", False)
        self.assertEqual(cf._with_patched(rng, {"patched_versions": "0.3.0"}), rng)
        self.assertIsNone(cf._with_patched(None, {"patched_versions": "0.3.0"}))

    def test_missing_or_unusable_patched_version(self):
        rng = ("0.1.0", None, False)
        for patched in (None, "", "latest", "0.0.9", "0.1.0"):
            self.assertEqual(cf._with_patched(rng, {"patched_versions": patched}), rng, patched)

    def test_advisory_ranges_uses_patched_version(self):
        adv = {"vulnerabilities": [{"package": {"ecosystem": "pip", "name": "vllm"},
                                    "vulnerable_version_range": ">=0.1.0", "patched_versions": "0.10.1.1"}]}
        ranges = cf.advisory_ranges(adv, "vllm")
        self.assertIn(("0.1.0", "0.10.1.1", False), [tuple(r) for r in ranges])


if __name__ == "__main__":
    unittest.main()
