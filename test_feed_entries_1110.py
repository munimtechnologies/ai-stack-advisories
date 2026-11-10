# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# The two vLLM advisories published 9 November 2026 stay in advisories.json with the ranges they state:
# GHSA-v97p-wpxp-px84 ">= 0.16.0, < 0.21.0" and GHSA-fpch-3xrf-7q96 ">= 0.21.0, < 0.28.0".
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECT = {("vllm", "GHSA-v97p-wpxp-px84"): {("0.16.0", "0.21.0")},
          ("vllm", "GHSA-fpch-3xrf-7q96"): {("0.21.0", "0.28.0")}}


class Entries1110(unittest.TestCase):
    def test_each_advisory_has_its_range(self):
        with open(os.path.join(HERE, "advisories.json"), encoding="utf-8") as f:
            feed = json.load(f)
        missing = []
        for (app, ghsa), ranges in sorted(EXPECT.items()):
            got = {(e.get("introduced"), e.get("fixed")) for e in feed["products"][app]["items"]
                   if ghsa in (e.get("ids") or [])}
            if not ranges <= got:
                missing.append("%s %s: want %s, have %s" % (app, ghsa, sorted(ranges), sorted(got, key=str)))
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
