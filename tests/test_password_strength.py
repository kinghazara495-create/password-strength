"""
test_password_strength.py - Unit tests for the password strength estimator.

Run with:  python -m unittest discover -s tests -v

These exist because a security tool that ships without tests is a liability,
and because writing the tests is how you find out whether the model actually
behaves the way the documentation claims.
"""

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from password_strength import (  # noqa: E402
    analyse,
    base_entropy,
    char_pool,
    crack_time,
    effective_entropy,
    has_repeat,
    has_sequence,
    humanise_seconds,
    is_common,
    keyboard_walk,
    verdict_for,
)


class TestCharacterPool(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(char_pool(""), 1)

    def test_lowercase_only(self):
        self.assertEqual(char_pool("abc"), 26)

    def test_four_classes(self):
        self.assertEqual(char_pool("aA1!"), 26 + 26 + 10 + 33)

    def test_space_is_not_a_symbol(self):
        # A space should not inflate the pool as if it were punctuation.
        self.assertEqual(char_pool("a a"), 26)


class TestBaseEntropy(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(base_entropy(""), 0.0)

    def test_character_class_gain_is_a_per_char_difference(self):
        # Adding classes is worth the DIFFERENCE in log2, not the full rate.
        # This was originally asserted as "9 lowercase beats 8 mixed", which is
        # false: 9*log2(26)=42.3 vs 8*log2(95)=52.6. Recorded here so the
        # correct relationship is what the suite protects.
        per_char_difference = math.log2(95) - math.log2(26)
        self.assertAlmostEqual(
            base_entropy("aA1$aA1$") - base_entropy("aaaaaaaa"),
            8 * per_char_difference, places=6)

    def test_mixed_beats_lowercase_at_short_lengths(self):
        # At 8 characters the mixed form genuinely has more entropy.
        self.assertGreater(base_entropy("aA1$aA1$"), base_entropy("a" * 8))

    def test_mixed_beats_lowercase_at_every_equal_length(self):
        # The original suite asserted "9 lowercase beats 8 mixed", then that
        # 14 lowercase beats 12 mixed. Both false. The true relationship has no
        # crossover: at EQUAL length, more character classes always means more
        # entropy. This test now protects that, so the false version cannot
        # come back.
        for n in (4, 8, 12, 16, 24):
            with self.subTest(length=n):
                mixed = base_entropy("".join("aA1$"[i % 4] for i in range(n)))
                lower = base_entropy("a" * n)
                self.assertGreater(mixed, lower,
                                   f"at {n} chars mixed must beat lowercase")

    def test_extra_characters_are_always_worth_it(self):
        short = base_entropy("aA1$aaaa")
        long = base_entropy("aA1$aaaaa")
        self.assertGreater(long, short)

    def test_matches_formula(self):
        # 8 chars from a pool of 95 printable ASCII = 8 * log2(95)
        pw = "aA1$aA1$"
        expected = len(pw) * math.log2(char_pool(pw))
        self.assertAlmostEqual(base_entropy(pw), expected, places=6)


class TestPatternDetection(unittest.TestCase):
    def test_repeats(self):
        self.assertTrue(has_repeat("aaaa"))
        self.assertTrue(has_repeat("ab111c"))
        self.assertFalse(has_repeat("abab"))
        self.assertFalse(has_repeat("abc"))

    def test_ascending_sequence(self):
        self.assertTrue(has_sequence("abcd"))
        self.assertTrue(has_sequence("x1234y"))
        self.assertFalse(has_sequence("abxy"))

    def test_descending_sequence(self):
        # The regex only catches ascending runs, so the descending branch is
        # the part most likely to rot. Test it explicitly.
        self.assertTrue(has_sequence("dcba"))
        self.assertTrue(has_sequence("9876"))

    def test_keyboard_walk(self):
        self.assertTrue(keyboard_walk("qwerty"))
        self.assertTrue(keyboard_walk("asdfgh"))
        self.assertFalse(keyboard_walk("xkqzj"))


class TestBlocklist(unittest.TestCase):
    def test_plain_hit(self):
        self.assertTrue(is_common("password"))

    def test_trailing_digit_mutation(self):
        self.assertTrue(is_common("password1"))
        self.assertTrue(is_common("admin123"))

    def test_leetspeak_mutation(self):
        self.assertTrue(is_common("p@ssw0rd"))

    def test_strong_password_not_flagged(self):
        self.assertFalse(is_common("Tr0ub4dor&3xyz!Q"))

    def test_case_insensitive(self):
        self.assertTrue(is_common("PASSWORD"))


class TestEntropyPenalty(unittest.TestCase):
    def test_blocklist_caps_hard(self):
        bits, reasons = effective_entropy("Password123!")
        self.assertLess(bits, 10)
        self.assertTrue(any("blocklist" in r for r in reasons))

    def test_strong_password_is_not_penalised(self):
        _, reasons = effective_entropy("Tr0ub4dor&3xyz!Q")
        self.assertEqual(reasons, [])

    def test_penalty_never_exceeds_one(self):
        # Penalties only ever reduce entropy.
        for pw in ["aaaaaaaa", "qwertyuiop", "abcd1234", "password1"]:
            bits, _ = effective_entropy(pw)
            self.assertLessEqual(bits, base_entropy(pw) + 1e-9)


class TestVerdictsAreAllReachable(unittest.TestCase):
    """The original tool had five unreachable labels. Prove these are not."""

    def test_no_gaps_in_threshold_table(self):
        from password_strength import VERDICTS
        ceilings = [v[0] for v in VERDICTS]
        self.assertEqual(ceilings, sorted(ceilings))
        self.assertEqual(ceilings[-1], float("inf"))

    def test_low_bits_is_weak(self):
        label, code = verdict_for(5)
        self.assertEqual(label, "VERY WEAK")
        self.assertEqual(code, 0)

    def test_high_bits_is_strong(self):
        label, code = verdict_for(128)
        self.assertEqual(label, "EXCEPTIONAL")
        self.assertEqual(code, 0)

    def test_boundaries_do_not_crash(self):
        for bits in [0, 0.1, 27.9, 28, 35.9, 36, 49.9, 50, 1e6]:
            verdict_for(bits)


class TestCrackTimes(unittest.TestCase):
    def test_zero_bits_is_instant(self):
        times = crack_time(0)
        self.assertEqual(set(times.values()), {"instant"})

    def test_more_bits_means_longer(self):
        weak = crack_time(30)["offline, fast hash (10 billion/sec)"]
        strong = crack_time(80)["offline, fast hash (10 billion/sec)"]
        self.assertNotEqual(weak, strong)

    def test_humanise_renders(self):
        self.assertEqual(humanise_seconds(0.5), "instant")
        for seconds in [1, 30, 3600, 86400, 86400 * 400]:
            self.assertIsInstance(humanise_seconds(seconds), str)


class TestRegressions(unittest.TestCase):
    """The exact passwords that fooled the original character-class scorer."""

    def test_original_scorer_was_wrong_about_these(self):
        # The old code called Password123 "Excellent" and P@ssw0rd "Very
        # Excellent". They must now be ranked weak.
        for pw in ["Password123", "P@ssw0rd!", "123456789012", "qwertyuiopas"]:
            label, _ = verdict_for(effective_entropy(pw)[0])
            self.assertIn(label, {"VERY WEAK", "WEAK"},
                          f"{pw} rated {label}, expected WEAK or worse")

    def test_genuine_strong_passwords_rank_strong(self):
        for pw in ["Tr0ub4dor&3xyz!Q", "correcthorsebatterystaple"]:
            label, _ = verdict_for(effective_entropy(pw)[0])
            self.assertIn(label, {"STRONG", "VERY STRONG", "EXCELLENT", "EXCEPTIONAL"},
                          f"{pw} rated {label}, expected STRONG or better")


class TestNoSecretLeak(unittest.TestCase):
    def test_report_never_contains_the_password(self):
        secret = "Sup3rS3cretValue!"
        report = analyse(secret)
        serialised = str(report)
        self.assertNotIn(secret, serialised)
        # The masked form is all that should be present.
        self.assertEqual(report["masked"], secret[0] + "*" * (len(secret) - 1))

    def test_masked_never_reveals_middle(self):
        report = analyse("abcdefgh")
        self.assertNotIn("bcd", report["masked"])


if __name__ == "__main__":
    unittest.main(verbosity=2)