# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# vLLM GHSA-mwgq-9582-w2vf (published 7 November 2026) stays in advisories.json, in an entry fixed in 0.30.0
# that starts at 0.3.0, as the advisory states (">= 0.3.0, < 0.30.0").
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECT = {("vllm", "GHSA-mwgq-9582-w2vf"): {("0.3.0", "0.30.0")}}


class Entries1107(unittest.TestCase):
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
