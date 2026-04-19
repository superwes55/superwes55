"""Unit tests for the entropy module."""

import pytest
from secretscope.engine.entropy import (
    BASE64_CHARSET,
    HEX_CHARSET,
    entropy_for_secret,
    is_high_entropy,
    shannon_entropy,
)


class TestShannonEntropy:
    def test_empty_string_returns_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_char_repeated_returns_zero(self) -> None:
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_two_equal_chars_returns_one(self) -> None:
        # 2 symbols, 50/50 split → entropy = 1.0
        assert shannon_entropy("abababab") == pytest.approx(1.0, abs=1e-9)

    def test_high_entropy_random_like_string(self) -> None:
        # This string has high character diversity
        s = "aB3$xQ9!mN2@kL7#pZ5^"
        assert shannon_entropy(s) > 3.5

    def test_charset_filter_excludes_non_charset_chars(self) -> None:
        # Only 'a' survives the hex charset filter → entropy = 0
        ent = shannon_entropy("aaaa____", charset=HEX_CHARSET)
        assert ent == 0.0

    def test_charset_filter_base64(self) -> None:
        # A typical base64-encoded secret has high entropy under BASE64_CHARSET
        b64_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ent = shannon_entropy(b64_secret, charset=BASE64_CHARSET)
        assert ent > 4.0

    def test_charset_none_uses_full_string(self) -> None:
        diverse = "0123456789abcdefghijklmnopqrstuvwxyz"
        assert shannon_entropy(diverse) > 5.0

    def test_returns_float(self) -> None:
        result = shannon_entropy("hello world")
        assert isinstance(result, float)


class TestIsHighEntropy:
    def test_low_entropy_fails(self) -> None:
        assert not is_high_entropy("aaaaaaaaaa", threshold=1.0)

    def test_high_entropy_passes(self) -> None:
        diverse = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789!@#$"
        assert is_high_entropy(diverse, threshold=4.0)

    def test_threshold_boundary(self) -> None:
        two_chars = "abababababababab"
        assert is_high_entropy(two_chars, threshold=1.0)
        assert not is_high_entropy(two_chars, threshold=1.001)


class TestEntropyForSecret:
    def test_aws_key_like_string(self) -> None:
        # 40-char base64 string resembling an AWS secret key
        key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert entropy_for_secret(key) > 4.5

    def test_low_entropy_not_flagged(self) -> None:
        assert entropy_for_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") < 1.0

    def test_returns_maximum_across_charsets(self) -> None:
        # A hex-heavy string should score high under hex charset
        hex_key = "deadbeef" * 4  # 32 hex chars
        result = entropy_for_secret(hex_key)
        assert result > 0
