# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# The 7 repository advisories that the 6 November 2026 freshness sweep found unflagged stay in advisories.json,
# each in an entry whose fixed version is the one its advisory names as patched.
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECT = {
    ("vllm", "GHSA-q9v9-qpjp-fc24"): {"0.33.0"},
    ("vllm", "GHSA-5r3c-5x4v-8gjh"): {"0.33.0"},
    ("vllm", "GHSA-qrj2-j723-m6w8"): {"0.33.0"},
    ("langflow", "GHSA-qvqp-mxh4-f27w"): {"1.13.0"},
    ("mcpinspector", "GHSA-h9j8-vj8g-v3gg"): {"2.14.0"},
    ("mcpinspector", "GHSA-rwv7-mh2c-ff2p"): {"2.14.0"},
    ("mcpinspector", "GHSA-2fw8-7jmw-r937"): {"2.14.0", "1.0.4"},
}


class Entries1106(unittest.TestCase):
    def test_each_advisory_has_its_fixed_versions(self):
        with open(os.path.join(HERE, "advisories.json"), encoding="utf-8") as f:
            feed = json.load(f)
        missing = []
        for (app, ghsa), fixes in sorted(EXPECT.items()):
            got = {e.get("fixed") for e in feed["products"][app]["items"] if ghsa in (e.get("ids") or [])}
            if not fixes <= got:
                missing.append("%s %s: want %s, have %s" % (app, ghsa, sorted(fixes), sorted(x or "" for x in got)))
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
