#!/usr/bin/env python3
"""PassGuard - score a password and explain how to make it stronger.

Runs entirely on your own machine. The password is never printed or saved.
"""

import getpass
import hashlib
import math
import re
import string
from pathlib import Path

import requests

COMMON_FILE = Path(__file__).parent / "common.txt"
MIN_LENGTH = 8
MAX_SCORE = 7
PATTERN_PENALTY = 2          # points removed for each kind of pattern found
MIN_SEQUENCE = 4             # shortest keyboard run that counts, e.g. "1234"
MIN_WORD = 4                 # shortest common word that counts
GUESSES_PER_SECOND = 10_000_000_000   # a fast offline attack

PWNED_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
PWNED_TIMEOUT = 5

# Runs of MIN_SEQUENCE characters from these count anywhere.
ORDERED_ROWS = ["1234567890", "abcdefghijklmnopqrstuvwxyz"]
# Letter rows need one more character, because ordinary words contain short
# pieces of them ("property" contains "erty"). The start of a row, such as
# "qwer" or "asdf", still counts at MIN_SEQUENCE.
LETTER_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]


# ---------------------------------------------------------------- week 1 rules

def check_length(pw):
    """Return 0-3 points depending on how long the password is."""
    if len(pw) >= 16:
        return 3
    if len(pw) >= 12:
        return 2
    if len(pw) >= MIN_LENGTH:
        return 1
    return 0


def check_lowercase(pw):
    return 1 if any(c.islower() for c in pw) else 0


def check_uppercase(pw):
    return 1 if any(c.isupper() for c in pw) else 0


def check_digits(pw):
    return 1 if any(c.isdigit() for c in pw) else 0


def check_symbols(pw):
    return 1 if any(c in string.punctuation for c in pw) else 0


def base_score(pw):
    """Week 1 score (0-7): length plus one point per character type."""
    return (check_length(pw) + check_lowercase(pw) + check_uppercase(pw)
            + check_digits(pw) + check_symbols(pw))


def rate(score):
    """Map a total score (0-7) to a label."""
    if score >= 6:
        return "Strong"
    if score >= 4:
        return "Medium"
    return "Weak"


# --------------------------------------------------------------------- entropy

def pool_size(pw):
    """Size of the character set the password appears to be drawn from."""
    size = 0
    if any(c.islower() for c in pw):
        size += 26
    if any(c.isupper() for c in pw):
        size += 26
    if any(c.isdigit() for c in pw):
        size += 10
    if any(c in string.punctuation for c in pw):
        size += len(string.punctuation)
    if any(not c.isalnum() and c not in string.punctuation for c in pw):
        size += 1   # spaces and other characters
    if any(c.isalpha() and not c.isascii() for c in pw):
        size += 26  # non-English letters
    return size


def estimate_entropy(pw):
    """Estimated entropy in bits: length * log2(pool_size)."""
    size = pool_size(pw)
    if size == 0:
        return 0.0
    return len(pw) * math.log2(size)


def seconds_to_guess(entropy_bits, guesses_per_second=GUESSES_PER_SECOND):
    """Average time to guess: half of all combinations at the given speed."""
    return 2 ** entropy_bits / 2 / guesses_per_second


def describe_time(seconds):
    """Turn a number of seconds into plain English."""
    if seconds < 1:
        return "less than a second"
    units = [("minute", 60), ("hour", 3600), ("day", 86400),
             ("month", 86400 * 30), ("year", 86400 * 365)]
    name, size = "second", 1
    for unit_name, unit_size in units:
        if seconds >= unit_size:
            name, size = unit_name, unit_size
    amount = seconds / size
    if name == "year":
        if amount >= 1e9:
            return "more than a billion years"
        if amount >= 1e6:
            return f"about {round(amount / 1e6)} million years"
        if amount >= 1e3:
            return f"about {round(amount / 1e3)} thousand years"
    amount = round(amount)
    return f"about {amount} {name}{'s' if amount != 1 else ''}"


# -------------------------------------------------------------------- patterns

def load_common(path=COMMON_FILE):
    """Load the common-password list (one per line). Missing file -> empty set."""
    try:
        with open(path, encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def is_common(pw, common):
    """True if the whole password is on the common list."""
    return pw.lower() in common


def has_common_word(pw, common):
    """True if a common word such as 'password' appears inside the password."""
    lowered = pw.lower()
    words = (w for w in common if w.isalpha() and len(w) >= MIN_WORD)
    return any(word in lowered for word in words)


def has_keyboard_sequence(pw, min_run=MIN_SEQUENCE):
    """True for runs like 'qwer', '1234' or 'dcba' (forwards or backwards)."""
    lowered = pw.lower()
    if any(_contains_run(lowered, row, min_run) for row in ORDERED_ROWS):
        return True
    for row in LETTER_ROWS:
        if row[:min_run] in lowered or row[:min_run][::-1] in lowered:
            return True
        if _contains_run(lowered, row, min_run + 1):
            return True
    return False


def _contains_run(text, row, run):
    """True if text contains `run` neighbouring characters of row, either direction."""
    for direction in (row, row[::-1]):
        for i in range(len(direction) - run + 1):
            if direction[i:i + run] in text:
                return True
    return False


def has_repeated_chars(pw):
    """True if the same character appears three or more times in a row."""
    return re.search(r"(.)\1{2,}", pw) is not None


def has_year(pw):
    """True if the password contains a year from 1900 to 2099."""
    return re.search(r"(?<!\d)(19|20)\d{2}(?!\d)", pw) is not None


def find_patterns(pw, common):
    """Return a list of (name, tip) for every predictable pattern found."""
    found = []
    if has_common_word(pw, common):
        found.append(("common word", "Avoid common words - use something unpredictable"))
    if has_keyboard_sequence(pw):
        found.append(("keyboard sequence", "Avoid keyboard sequences like qwerty or 1234"))
    if has_repeated_chars(pw):
        found.append(("repeated characters", "Avoid repeating the same character"))
    if has_year(pw):
        found.append(("year", "Avoid years such as a birth year or the current year"))
    return found


# ----------------------------------------------- breach check (k-anonymity)

_PREFIX_CACHE = {}


def pwned_hash(pw):
    """Return (prefix, suffix) of SHA-1 hash for k-anonymity.

    The first 5 characters (prefix) are sent to the API.
    The remaining 35 characters (suffix) stay local to search the response.
    """
    sha1_hex = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    return sha1_hex[:5], sha1_hex[5:]


def query_pwned_range(prefix, timeout=PWNED_TIMEOUT, cache=None):
    """Query Have I Been Pwned range API for hash prefix.

    Returns a dict mapping suffix -> breach count.
    Results are cached to avoid repeated API requests for the same prefix.
    """
    prefix = prefix.upper()
    target_cache = _PREFIX_CACHE if cache is None else cache
    if prefix in target_cache:
        return target_cache[prefix]

    url = PWNED_API_URL.format(prefix=prefix)
    headers = {"User-Agent": "PassGuard-Breach-Checker"}
    response = requests.get(url, timeout=timeout, headers=headers)
    response.raise_for_status()

    hashes = {}
    for line in response.text.splitlines():
        line = line.strip()
        if ":" in line:
            suffix, count_str = line.split(":", 1)
            try:
                hashes[suffix.upper()] = int(count_str.strip())
            except ValueError:
                continue

    target_cache[prefix] = hashes
    return hashes


def check_breach(pw, timeout=PWNED_TIMEOUT, cache=None):
    """Check Have I Been Pwned for breaches using k-anonymity.

    Returns a dict with:
      - status: "ok" or "error"
      - breached: bool (True if breach count > 0)
      - count: int (number of times seen in breaches, or 0)
      - prefix: str (the 5-char prefix checked)
      - error: str or None (user-friendly error message if failed)
    """
    prefix, suffix = pwned_hash(pw)
    try:
        prefix_data = query_pwned_range(prefix, timeout=timeout, cache=cache)
        count = prefix_data.get(suffix, 0)
        return {
            "status": "ok",
            "breached": count > 0,
            "count": count,
            "prefix": prefix,
            "error": None,
        }
    except requests.RequestException:
        return {
            "status": "error",
            "breached": False,
            "count": 0,
            "prefix": prefix,
            "error": "offline or network error (could not verify breach status)",
        }


# ------------------------------------------------------------------ evaluation

def rule_tips(pw):
    """Tips for the week 1 rules the password does not meet."""
    tips = []
    length_score = check_length(pw)
    if length_score == 0:
        tips.append(f"Use at least {MIN_LENGTH} characters (12 or more is better)")
    elif length_score < 3:
        tips.append("Make it longer - 16 or more characters gets the full length score")
    if not check_lowercase(pw):
        tips.append("Add at least one lowercase letter")
    if not check_uppercase(pw):
        tips.append("Add at least one uppercase letter")
    if not check_digits(pw):
        tips.append("Add at least one digit")
    if not check_symbols(pw):
        tips.append("Add at least one symbol (e.g. ! @ # $ %)")
    return tips


def evaluate(pw, common=None, check_pwned=True, pwned_cache=None, timeout=PWNED_TIMEOUT):
    """Return a dict describing the password. The password itself is not included."""
    if common is None:
        common = load_common()

    base = base_score(pw)
    patterns = find_patterns(pw, common)
    score = max(0, base - PATTERN_PENALTY * len(patterns))
    rating = rate(score)
    tips = [tip for _, tip in patterns] + rule_tips(pw)

    # A short password is weak no matter how many character types it has.
    if check_length(pw) == 0:
        rating = "Weak"

    # A known common password is weak immediately.
    common_password = is_common(pw, common)
    if common_password:
        rating = "Weak"
        tips.insert(0, "This is one of the most common passwords - choose something unique")

    breach_info = None
    if check_pwned:
        breach_info = check_breach(pw, timeout=timeout, cache=pwned_cache)
        if breach_info["status"] == "ok" and breach_info["breached"]:
            rating = "Weak"
            tips.insert(0, f"Found in {breach_info['count']:,} known data breaches - do not use this password")

    entropy = estimate_entropy(pw)
    if common_password:
        time_to_guess = "instantly (it is on common password lists)"
    else:
        time_to_guess = describe_time(seconds_to_guess(entropy))

    return {
        "score": score,
        "base_score": base,
        "rating": rating,
        "entropy_bits": entropy,
        "time_to_guess": time_to_guess,
        "common_password": common_password,
        "patterns": [name for name, _ in patterns],
        "tips": tips,
        "breach": breach_info,
    }


def print_report(result):
    score_line = f"Score:   {result['score']}/{MAX_SCORE}"
    if result["score"] != result["base_score"]:
        score_line += f" ({result['base_score']} before pattern penalties)"
    print(f"\n{score_line}")
    print(f"Rating:  {result['rating']}")
    print(f"Entropy: about {result['entropy_bits']:.1f} bits (estimate)")
    print(f"Time to guess: {result['time_to_guess']}")
    if not result["common_password"]:
        print(f"  at {GUESSES_PER_SECOND:,} guesses per second, trying every combination")
        if result["patterns"]:
            print("  patterns were found, so a real attacker would be much faster")

    if result.get("breach"):
        breach = result["breach"]
        if breach["status"] == "ok":
            if breach["breached"]:
                print(f"Breach:  Found in {breach['count']:,} known data breaches!")
            else:
                print("Breach:  Safe (no matches found in known data breaches)")
        else:
            print(f"Breach:  Check unavailable ({breach['error']})")

    if result["patterns"]:
        print("\nPatterns found:")
        for name in result["patterns"]:
            print(f"  - {name}")

    if result["tips"]:
        print("\nTips:")
        for tip in result["tips"]:
            print(f"  - {tip}")
    else:
        print("\nNo tips - this password passes every rule.")


def main():
    print("PassGuard - password strength checker")
    print("Your input is hidden and is never printed or stored.\n")

    pw = getpass.getpass("Enter a password to check: ")
    if not pw:
        print("No password entered.")
        return

    print_report(evaluate(pw))


if __name__ == "__main__":
    main()
