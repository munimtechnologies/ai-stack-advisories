# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
"""action.yml must stay publishable on GitHub Marketplace.

Marketplace refuses a release whose action.yml description is 125 characters or longer, and it needs a
name, a runs section and branding. These checks read the file as text so they need no YAML library.
"""
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ACTION = os.path.join(HERE, "action.yml")


def top_level(path):
    """Map each top-level key of a simple YAML file to its raw one-line value (quotes removed)."""
    keys = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip() or line[0] in " \t#" or ":" not in line:
                continue
            key, _, value = line.partition(":")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            keys.setdefault(key.strip(), []).append(value)
    return keys


class ActionMetadataTest(unittest.TestCase):
    def setUp(self):
        self.keys = top_level(ACTION)

    def test_one_name_and_description(self):
        self.assertEqual(len(self.keys.get("name", [])), 1)
        self.assertEqual(len(self.keys.get("description", [])), 1)
        self.assertTrue(self.keys["name"][0])

    def test_description_fits_marketplace(self):
        description = self.keys["description"][0]
        self.assertNotIn(description, ("", ">", "|", ">-", "|-"), "description must be one line")
        self.assertLess(len(description), 125)
        self.assertIn("advisories", description)

    def test_runs_and_branding(self):
        self.assertIn("runs", self.keys)
        self.assertIn("branding", self.keys)


if __name__ == "__main__":
    unittest.main()
