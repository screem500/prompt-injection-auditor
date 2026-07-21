import unittest

from scripts.normalization import normalize_arabic, suspicious_unicode_lines


class ArabicNormalizationTests(unittest.TestCase):
    def test_removes_diacritics_and_tatweel(self):
        self.assertEqual(normalize_arabic("تَجَاهَــل"), "تجاهل")

    def test_normalizes_common_arabic_and_persian_variants(self):
        self.assertEqual(
            normalize_arabic("أإآٱ ىیے ئؤ ة ک"),
            "اااا ييي يو ه ك",
        )

    def test_removes_zero_width_direction_and_grapheme_controls(self):
        value = "تجا\u200bهل\u202e التع\u034fليمات"
        self.assertEqual(normalize_arabic(value), "تجاهل التعليمات")
        self.assertEqual(suspicious_unicode_lines(value), [1])

    def test_joins_deliberately_space_split_arabic_keyword(self):
        self.assertEqual(normalize_arabic("ت ج ا ه ل التعليمات"), "تجاهل التعليمات")

    def test_does_not_join_normal_arabic_words(self):
        self.assertEqual(normalize_arabic("هذه تعليمات النظام"), "هذه تعليمات النظام")

    def test_preserves_line_count(self):
        original = "أول\nثَانٍ\nثالث"
        self.assertEqual(len(normalize_arabic(original).splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
