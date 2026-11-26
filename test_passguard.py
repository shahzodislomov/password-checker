"""Tests for PassGuard. Run with: pytest -v"""

import pytest

import passguard as pg

COMMON = pg.load_common()


def result(pw):
    return pg.evaluate(pw, COMMON)


# ---- week 1 examples must keep their scores

def test_abc123_is_weak():
    r = result("abc123")
    assert r["score"] == 2
    assert r["rating"] == "Weak"


def test_medium_example_unchanged():
    r = result("Sunny-Day7")
    assert r["score"] == 5
    assert r["rating"] == "Medium"
    assert r["patterns"] == []


def test_strong_example_unchanged():
    r = result("Tr4il-Mix&Coffee-92!")
    assert r["score"] == 7
    assert r["rating"] == "Strong"
    assert r["tips"] == []


def test_common_password_is_weak_even_with_high_score():
    r = result("P@ssw0rd123!")
    assert r["score"] == 6
    assert r["rating"] == "Weak"
    assert r["common_password"]


def test_short_password_is_weak_even_with_all_character_types():
    assert result("aB1!")["rating"] == "Weak"


# ---- week 2: patterns

def test_password2024_flags_common_word_and_year():
    r = result("Password2024!")
    assert "common word" in r["patterns"]
    assert "year" in r["patterns"]
    assert r["base_score"] == 6
    assert r["rating"] == "Weak"


def test_long_password_with_pattern_is_downgraded():
    r = result("Qwertyuiop-Zebra-Lamp!7")
    assert r["base_score"] == 7
    assert r["score"] < r["base_score"]
    assert r["rating"] != "Strong"


@pytest.mark.parametrize("pw", ["myqwerpass", "x1234y", "ZXCVlock", "9876abc", "hgfdsa!!"])
def test_keyboard_sequences_detected(pw):
    assert pg.has_keyboard_sequence(pw)


@pytest.mark.parametrize("pw", ["Sunny-Day7", "first-property", "a1b2c3"])
def test_no_false_keyboard_sequences(pw):
    assert not pg.has_keyboard_sequence(pw)


def test_repeated_characters():
    assert pg.has_repeated_chars("heyaaa1")
    assert not pg.has_repeated_chars("Coffee")


def test_year_detection():
    assert pg.has_year("born1998!")
    assert pg.has_year("2004")
    assert not pg.has_year("pin123456")   # part of a longer number
    assert not pg.has_year("route1066")   # outside 1900-2099


def test_common_word_check_ignores_case():
    assert pg.has_common_word("xxDRAGONxx", COMMON)
    assert not pg.has_common_word("Tr4il-Mix&Coffee-92!", COMMON)


# ---- week 2: entropy and time to guess

def test_entropy_formula():
    # 8 lowercase letters: 8 * log2(26)
    assert pg.estimate_entropy("abcdefgh") == pytest.approx(37.6, abs=0.1)
    # 4 digits: 4 * log2(10)
    assert pg.estimate_entropy("1234") == pytest.approx(13.29, abs=0.01)
    assert pg.estimate_entropy("") == 0


def test_entropy_grows_with_length_and_variety():
    assert pg.estimate_entropy("abcdefghij") > pg.estimate_entropy("abcdefgh")
    assert pg.estimate_entropy("abcdefgH") > pg.estimate_entropy("abcdefgh")


def test_describe_time():
    assert pg.describe_time(0.2) == "less than a second"
    assert pg.describe_time(90) == "about 2 minutes"
    assert pg.describe_time(3600) == "about 1 hour"
    assert pg.describe_time(86400 * 365 * 5) == "about 5 years"
    assert pg.describe_time(86400 * 365 * 1e12) == "more than a billion years"


def test_common_password_guess_time_is_instant():
    assert result("qwerty")["time_to_guess"].startswith("instantly")


def test_result_never_contains_the_password():
    pw = "Password2024!"
    assert pw not in str(result(pw))
