# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# Every advisories.json entry carries a rating in GitHub's words, so a severity filter never drops an entry
# just because its rating was left empty (10 entries were, until 31 October 2026).
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WORDS = ("LOW", "MODERATE", "HIGH", "CRITICAL")


class SeverityFilled(unittest.TestCase):
    def test_every_entry_has_a_rating(self):
        with open(os.path.join(HERE, "advisories.json"), encoding="utf-8") as f:
            feed = json.load(f)
        missing = ["%s #%d %s" % (app, n, e.get("ids")) for app, p in feed["products"].items()
                   for n, e in enumerate(p["items"]) if e.get("severity") not in WORDS]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
