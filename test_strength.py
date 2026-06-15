"""
Tests for the password strength checker.

Run with:  python3 -m unittest

These lock in the two most important rules:
  1. entropy goes up with length and character variety
  2. a known-common password is always rated Very Weak, no matter the math
"""

import unittest

from strength import entropy_bits, character_pool_size, check


COMMON = {"password1", "123456", "qwerty"}


class TestEntropy(unittest.TestCase):
    def test_empty_password_has_zero_entropy(self):
        self.assertEqual(entropy_bits(""), 0.0)

    def test_longer_password_has_more_entropy(self):
        short = entropy_bits("aaaaaa")
        long = entropy_bits("aaaaaaaaaaaa")
        self.assertGreater(long, short)

    def test_more_character_types_means_bigger_pool(self):
        self.assertGreater(character_pool_size("aA1!"), character_pool_size("aaaa"))


class TestCheck(unittest.TestCase):
    def test_common_password_is_always_very_weak(self):
        result = check("password1", COMMON)
        self.assertEqual(result["rating"], "Very Weak")
        self.assertTrue(any("common" in i for i in result["issues"]))

    def test_strong_passphrase_has_no_issues(self):
        result = check("Coffee-Sunset-River-92!", COMMON)
        self.assertEqual(result["rating"], "Very Strong")
        self.assertEqual(result["issues"], [])

    def test_short_password_is_flagged(self):
        result = check("aB3!", COMMON)
        self.assertTrue(any("short" in i for i in result["issues"]))


if __name__ == "__main__":
    unittest.main()
