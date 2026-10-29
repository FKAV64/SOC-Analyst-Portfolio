import pytest
import math

from password_checker import is_too_short
from password_checker import estimate_entropy
from password_checker import is_common_password
@pytest.mark.parametrize(
    ("password", "min_length", "expected"),
    [
        ("hello", 12, True),
        ("123456789012", 12, False),
        ("long-enough!", 12, False),
    ],
)
def test_is_too_short(password, min_length, expected):
    assert is_too_short(password, min_length) is expected

@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("", 0.0),
        ("abcd", 4 * math.log2(26)),
        ("a1", 2 * math.log2(36)),
        ("a!", 2 * math.log2(58)),
    ],
)
def test_estimate_entropy(password, expected):
    assert estimate_entropy(password) == pytest.approx(expected)

@pytest.mark.parametrize(
    ("password", "common_passwords", "expected"),
    [
        ("mx45abnd", {"mx45abnd", "123456"}, True),
        ("eapoesdfas", {"password", "123456"}, False),
    ]
)
def test_is_common_password(password, common_passwords, expected):
    assert is_common_password(password, common_passwords) is expected
