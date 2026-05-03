import re

# Zero-width and invisible Unicode characters attackers use to split keywords.
# e.g. inserting U+200B between letters in "ignore" evades the naive pattern.
# Shared by pipeline.py, provenance_scanner.py, and fuzzy_scanner.py.
# Keep this character set in sync with pipeline.py.
_ZERO_WIDTH_RE = re.compile(
    r'[­​‌‍\u200E\u200F⁠﻿]'
)


def strip_zero_width(text: str) -> str:
    """Remove zero-width and invisible Unicode characters from text."""
    return _ZERO_WIDTH_RE.sub('', text)
