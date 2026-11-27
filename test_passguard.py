"""Tests for PassGuard. Run with: pytest -v"""

from unittest.mock import patch
import pytest
import requests

import passguard as pg

COMMON = pg.load_common()


def result(pw):
    return pg.evaluate(pw, COMMON, check_pwned=False)


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


# ---- week 3: k-anonymity, HIBP range API, and offline handling

def test_pwned_hash_k_anonymity_split():
    # Known SHA-1 of "password": 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    prefix, suffix = pg.pwned_hash("password")
    assert prefix == "5BAA6"
    assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    assert len(prefix) == 5
    assert len(suffix) == 35
    assert prefix + suffix == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_api_sends_only_prefix():
    prefix, suffix = pg.pwned_hash("supersecretpassword123")
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = f"{suffix}:12\nABCDE:3"

        pg.check_breach("supersecretpassword123", cache={})

        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        assert called_url == f"https://api.pwnedpasswords.com/range/{prefix}"
        assert "supersecretpassword123" not in called_url
        assert suffix not in called_url


def test_password_reported_as_breached_with_count():
    prefix, suffix = pg.pwned_hash("mypassword")
    mock_response = f"00000000000000000000000000000000000:1\n{suffix}:4242\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:5"
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = mock_response

        res = pg.check_breach("mypassword", cache={})
        assert res["status"] == "ok"
        assert res["breached"] is True
        assert res["count"] == 4242
        assert res["error"] is None


def test_password_not_breached_when_suffix_absent():
    prefix, suffix = pg.pwned_hash("uniqueunbreachedpassword987654!")
    mock_response = "00000000000000000000000000000000000:1\n11111111111111111111111111111111111:5"
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = mock_response

        res = pg.check_breach("uniqueunbreachedpassword987654!", cache={})
        assert res["status"] == "ok"
        assert res["breached"] is False
        assert res["count"] == 0
        assert res["error"] is None


def test_offline_connection_error_handled_gracefully():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Network unreachable")):
        res = pg.check_breach("anypassword", cache={})
        assert res["status"] == "error"
        assert res["breached"] is False
        assert res["count"] == 0
        assert "offline or network error" in res["error"]


def test_offline_timeout_handled_gracefully():
    with patch("requests.get", side_effect=requests.exceptions.Timeout("Request timed out")):
        res = pg.check_breach("anypassword", cache={})
        assert res["status"] == "error"
        assert res["breached"] is False
        assert "offline or network error" in res["error"]


def test_evaluate_with_breach_forces_weak_and_adds_tip():
    prefix, suffix = pg.pwned_hash("Tr4il-Mix&Coffee-92!")
    mock_response = f"{suffix}:150"
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = mock_response

        r = pg.evaluate("Tr4il-Mix&Coffee-92!", COMMON, check_pwned=True, pwned_cache={})
        assert r["breach"]["status"] == "ok"
        assert r["breach"]["breached"] is True
        assert r["breach"]["count"] == 150
        assert r["rating"] == "Weak"
        assert any("150" in tip and "data breaches" in tip for tip in r["tips"])


def test_prefix_cache_prevents_duplicate_api_calls():
    cache = {}
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:50\n"

        # "password" has prefix 5BAA6
        res1 = pg.check_breach("password", cache=cache)
        assert mock_get.call_count == 1

        # Querying again with "password" should hit cache
        res2 = pg.check_breach("password", cache=cache)
        assert mock_get.call_count == 1
        assert res2["count"] == 50


def test_print_report_offline_resilience(capsys):
    fake_result = {
        "score": 5,
        "base_score": 5,
        "rating": "Medium",
        "entropy_bits": 65.5,
        "time_to_guess": "about 2 hours",
        "common_password": False,
        "patterns": [],
        "tips": [],
        "breach": {
            "status": "error",
            "breached": False,
            "count": 0,
            "prefix": "12345",
            "error": "offline or network error (could not verify breach status)",
        },
    }
    pg.print_report(fake_result)
    captured = capsys.readouterr().out
    assert "Check unavailable" in captured
    assert "offline or network error" in captured
