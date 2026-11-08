"""
Sentence BLEU similarity matcher against external known attack corpus.
"""

import re
import warnings
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from src.preprocessing.tokenizer import split_windows, split_linux

_RE_DIGITS = re.compile(r"[0-9]+")
DEFAULT_THRESHOLD = 0.5
MIN_TOKENS = 4
MIN_CMD_LEN = 6
MAX_CMD_LEN = 100
MAX_CORPUS_LEN = 100
MIN_CORPUS_LEN = 5


class SimilarityMatcher:
    """
    Computes token-level n-gram BLEU similarity against a reference corpus.
    """

    def __init__(self, corpus_path: str, platform: str = "windows"):
        self._platform = platform
        self._tokenizer = split_windows if platform == "windows" else split_linux
        self._corpus: list = self._load_corpus(corpus_path)
        self._index = defaultdict(set)
        for index, tokens in enumerate(self._corpus):
            for start in range(len(tokens) - 3):
                self._index[tuple(tokens[start:start + 4])].add(index)

    def _load_corpus(self, corpus_path: str) -> list:
        path = Path(corpus_path)
        if not path.exists():
            raise FileNotFoundError(f"Corpus file not found: {corpus_path}")

        corpus = []
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not (MIN_CORPUS_LEN <= len(line) <= MAX_CORPUS_LEN):
                    continue
                try:
                    # Use the same normalization as the candidate, including IPs,
                    # ports, version numbers and executable names such as regsvr32.
                    tokens = self._tokenizer(_RE_DIGITS.sub("0", line))
                    if len(tokens) >= MIN_TOKENS:
                        corpus.append(tokens)
                except Exception:
                    continue

        return corpus

    @lru_cache(maxsize=4096)
    def is_similar(self, command: str, threshold: float = DEFAULT_THRESHOLD) -> bool:
        """
        Check if the command yields a BLEU score exceeding threshold against any reference.
        """
        if not (MIN_CMD_LEN <= len(command) <= MAX_CMD_LEN):
            return False

        normalized = _RE_DIGITS.sub("0", command)
        try:
            candidate_tokens = self._tokenizer(normalized)
        except Exception:
            return False

        if len(candidate_tokens) < MIN_TOKENS:
            return False

        from nltk.translate.bleu_score import sentence_bleu

        # Unsmoothed BLEU cannot exceed 0.5 without a shared 4-gram.
        # Keep a full scan for other thresholds to preserve the public helper.
        if threshold >= 0.5:
            candidates = set()
            for start in range(len(candidate_tokens) - 3):
                candidates.update(self._index.get(tuple(candidate_tokens[start:start + 4]), ()))
            indices = sorted(candidates)
        else:
            indices = range(len(self._corpus))

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for index in indices:
                reference_tokens = self._corpus[index]
                score = sentence_bleu(
                    [reference_tokens],
                    candidate_tokens,
                    weights=(0.25, 0.25, 0.25, 0.25),
                )
                if score > threshold:
                    return True

        return False
