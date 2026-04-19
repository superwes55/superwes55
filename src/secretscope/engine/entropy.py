"""Shannon entropy utilities for secret-likelihood scoring."""

from __future__ import annotations

import math
import string
from collections import Counter

BASE64_CHARSET = string.ascii_letters + string.digits + "+/="
HEX_CHARSET = string.hexdigits


def shannon_entropy(text: str, charset: str | None = None) -> float:
    """Calculate Shannon entropy (bits per character) of *text*.

    If *charset* is supplied, only characters present in that set are counted;
    characters outside the set are discarded before computing entropy.  This
    lets you measure, e.g., the entropy of base64 content within a larger string
    that may contain punctuation or whitespace.
    """
    if charset is not None:
        text = "".join(c for c in text if c in charset)
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def is_high_entropy(text: str, threshold: float, charset: str | None = None) -> bool:
    """Return True when *text*'s entropy meets or exceeds *threshold*."""
    return shannon_entropy(text, charset) >= threshold


def entropy_for_secret(secret: str) -> float:
    """Return the highest entropy score across common secret charsets.

    Tries the base64 charset (most API keys), the hex charset, and the full
    printable charset, and returns the maximum.  This avoids false negatives
    where a key uses a limited alphabet that looks low-entropy under the full
    charset but is actually dense within its own alphabet.
    """
    return max(
        shannon_entropy(secret, BASE64_CHARSET),
        shannon_entropy(secret, HEX_CHARSET),
        shannon_entropy(secret),
    )
