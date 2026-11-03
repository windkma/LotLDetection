"""
Feature label generators that transform raw command strings into lists of symbolic security labels.

Classes:
- RegexLabelGenerator   : Generates labels from regular expressions with named capturing groups.
- KeywordLabelGenerator : Generates labels from lists of keywords or system paths.
"""

import re
from src.preprocessing.tokenizer import split_windows, split_linux


# PHẦN BỔ SUNG 2026-11-03: nhận diện tên binary, kể cả trong đường dẫn.
# Đây là đặc trưng hiện diện tên công cụ, không phải nhãn kết luận tấn công.
class BinaryLabelGenerator:
    """Recognize catalog tool names without changing the original command.

    Matches are lexical evidence, not proof that a tool was executed. Windows
    executable extensions are optional; Linux names remain case-sensitive.
    Word boundaries exclude longer filenames such as notcurl or curl-backup.
    """

    def __init__(self, binaries, platform):
        self._windows = platform == "windows"
        names = set()
        for binary in binaries:
            name = str(binary).replace("\\", "/").rsplit("/", 1)[-1]
            if self._windows:
                name = name.lower()
                name = re.sub(r"\.(?:exe|com|bat|cmd)$", "", name)
            if name:
                names.add(name)
        alternatives = "|".join(re.escape(name) for name in sorted(names, key=lambda n: (-len(n), n)))
        suffix = r"(?:\.(?:exe|com|bat|cmd))?" if self._windows else ""
        self._pattern = re.compile(
            rf"(?<![\w.+-])(?P<binary>{alternatives}){suffix}(?![\w.+-])",
            re.IGNORECASE if self._windows else 0,
        )

    def __call__(self, command):
        return list(dict.fromkeys(
            "BIN_" + match.group("binary").upper()
            for match in self._pattern.finditer(str(command))
        ))


class RegexLabelGenerator:
    def __init__(self, regex_patterns: list, platform: str = "linux"):
        """
        Args:
            regex_patterns: Independent regex rules with named capturing groups.
                Keep each feature rule separate: joining rules with | can hide
                overlapping matches. Each matching group name becomes a label.
        """
        flags = re.MULTILINE | (re.IGNORECASE if platform == "windows" else 0)
        self._compiled_patterns = [
            re.compile(pattern, flags)
            for pattern in regex_patterns
        ]

    def __call__(self, command: str) -> list:
        padded = f"  {command} "
        matched_labels = []

        for pattern in self._compiled_patterns:
            for match in pattern.finditer(padded):
                for group_name, group_value in match.groupdict().items():
                    if group_value is not None:
                        matched_labels.append(group_name)

        return matched_labels


class KeywordLabelGenerator:
    def __init__(self, prefix: str, keywords: list, tokenize: bool, platform: str = "linux"):
        """
        Args:
            prefix  : Label prefix (e.g. "COMMAND", "PATH", "KEYWORD").
            keywords: List of target strings.
            tokenize: Whether to match on tokens or substrings.
            platform: Platform name ("windows" or "linux").
        """
        self._prefix = prefix
        self._keywords_lower: set = {k.lower() for k in keywords}
        self._tokenize = tokenize
        self._platform = platform
        self._tokenizer = split_windows if platform == "windows" else split_linux

    def __call__(self, command: str) -> list:
        """
        Extracts matching keyword/path labels from command.

        Args:
            command: Input command string.

        Returns:
            List of unique generated labels.
        """
        command = str(command)
        found_labels: dict = {}

        if self._tokenize:
            try:
                tokens = self._tokenizer(command)
            except Exception:
                tokens = []

            for token in tokens:
                token_lower = token.lower()
                if token_lower in self._keywords_lower:
                    label = f"{self._prefix}_{token_lower}".upper()
                    found_labels[label] = True
        else:
            command_lower = command.lower()
            for keyword in self._keywords_lower:
                if keyword in command_lower:
                    label = f"{self._prefix}_{keyword}".upper()
                    found_labels[label] = True

        return list(found_labels.keys())
