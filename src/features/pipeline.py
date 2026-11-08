"""
Feature extraction pipeline for command strings.

Sequentially extracts:
  1. Bounded Windows shell analysis views (original text is preserved)
  2. IP address labels
  3. Sensitive path labels
  4. Known binary labels (LOLBins / GTFOBins)
  5. Keyword labels
  6. Behavioral regex patterns
  7. Corpus BLEU similarity matching (inference only)

Classes:
- WindowsFeaturePipeline
- LinuxFeaturePipeline
"""

from src.preprocessing.normalizer import windows_analysis_views, extract_ip_labels
from src.features.label_generators import RegexLabelGenerator, KeywordLabelGenerator
from src.features.similarity import SimilarityMatcher
from src.features.rules_constants import (
    WINDOWS_COMMANDS, WINDOWS_PATHS, WINDOWS_KEYWORDS, WINDOWS_REGEX_LIST,
    LINUX_COMMANDS, LINUX_PATHS, LINUX_KEYWORDS, LINUX_REGEX_LIST,
)

LABEL_LOOKS_LIKE_KNOWN_LOL = "LOOKS_LIKE_KNOWN_LOL"
MIN_LABELS_FOR_TRAINING = 1


class WindowsFeaturePipeline:
    """
    Feature extraction pipeline for Windows command lines.
    """

    def __init__(self, corpus_path: str):
        """
        Args:
            corpus_path: Path to known reference corpus file (.corpus or .txt).
        """
        self._ip_extractor = extract_ip_labels
        self._path_gen = KeywordLabelGenerator("PATH", WINDOWS_PATHS, tokenize=False, platform="windows")
        self._cmd_gen = KeywordLabelGenerator("COMMAND", WINDOWS_COMMANDS, tokenize=True, platform="windows")
        self._kw_gen = KeywordLabelGenerator("KEYWORD", WINDOWS_KEYWORDS, tokenize=True, platform="windows")
        self._regex_gen = RegexLabelGenerator(WINDOWS_REGEX_LIST, platform="windows")
        self._similarity = SimilarityMatcher(corpus_path, platform="windows")

    def __call__(self, command: str, training: bool = False) -> list:
        """
        Extracts symbolic feature labels from a Windows command line.

        Args:
            command : Raw command string.
            training: When True, skips BLEU corpus lookup for faster dataset preprocessing.

        Returns:
            List of unique feature labels.
        """
        labels: list = []
        for view in windows_analysis_views(command):
            labels.extend(self._ip_extractor(view))
            labels.extend(self._path_gen(view))
            labels.extend(self._cmd_gen(view))
            labels.extend(self._kw_gen(view))
            labels.extend(self._regex_gen(view))

            if not training and self._similarity.is_similar(view):
                labels.append(LABEL_LOOKS_LIKE_KNOWN_LOL)

        return list(dict.fromkeys(labels))


class LinuxFeaturePipeline:
    """
    Feature extraction pipeline for Linux/Bash command lines.
    """

    def __init__(self, corpus_path: str):
        """
        Args:
            corpus_path: Path to known reference corpus file (.corpus or .txt).
        """
        self._ip_extractor = extract_ip_labels
        self._path_gen = KeywordLabelGenerator("PATH", LINUX_PATHS, tokenize=False, platform="linux")
        self._cmd_gen = KeywordLabelGenerator("COMMAND", LINUX_COMMANDS, tokenize=True, platform="linux")
        self._kw_gen = KeywordLabelGenerator("KEYWORD", LINUX_KEYWORDS, tokenize=True, platform="linux")
        self._regex_gen = RegexLabelGenerator(LINUX_REGEX_LIST, platform="linux")
        self._similarity = SimilarityMatcher(corpus_path, platform="linux")

    def __call__(self, command: str, training: bool = False) -> list:
        """
        Extracts symbolic feature labels from a Linux command line.

        Args:
            command : Raw command string.
            training: When True, skips BLEU corpus lookup.

        Returns:
            List of unique feature labels.
        """
        command = str(command)

        labels: list = []
        labels.extend(self._ip_extractor(command))
        labels.extend(self._path_gen(command))
        labels.extend(self._cmd_gen(command))
        labels.extend(self._kw_gen(command))
        labels.extend(self._regex_gen(command))

        if not training and self._similarity.is_similar(command):
            labels.append(LABEL_LOOKS_LIKE_KNOWN_LOL)

        return list(dict.fromkeys(labels))
