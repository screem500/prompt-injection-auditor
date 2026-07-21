import unittest

from scripts.normalization import normalize_arabic, suspicious_unicode_lines


class ArabicNormalizationTests(unittest.TestCase):
    def test_removes_diacritics_and_tatweel(self):
        self.assertEqual(normalize_arabic("تَجَاهَــل"), "تجاهل")

    def test_normalizes_alef_and_yeh_variants(self):
        self.assertEqual(normalize_arabic("أإآٱ ىی"), "اااا يي")

    def test_removes_zero_width_and_direction_controls(self):
        value = "تجا\u200bهل\u202e التعليمات"
        self.assertEqual(normalize_arabic(value), "تجاهل التعليمات")
        self.assertEqual(suspicious_unicode_lines(value), [1])

    def test_preserves_line_count(self):
        original = "أول\nثَانٍ\nثالث"
        self.assertEqual(len(normalize_arabic(original).splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
