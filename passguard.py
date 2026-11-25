#!/usr/bin/env python3
"""PassGuard - score a password and explain how to make it stronger.

Runs entirely on your own machine. The password is never printed or saved.
"""

import getpass
import string
from pathlib import Path

COMMON_PASSWORDS_FILE = Path(__file__).parent / "common_passwords.txt"
MIN_LENGTH = 8
MAX_SCORE = 7


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


def load_common_passwords(path=COMMON_PASSWORDS_FILE):
    """Load the common-password list (one per line). Missing file -> empty set."""
    try:
        with open(path, encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def is_common(pw, common):
    return pw.lower() in common


def rate(score):
    """Map a total score (0-7) to a label."""
    if score >= 6:
        return "Strong"
    if score >= 4:
        return "Medium"
    return "Weak"


def evaluate(pw, common=None):
    """Return (score, rating, tips) for a password."""
    if common is None:
        common = load_common_passwords()

    tips = []

    length_score = check_length(pw)
    if length_score == 0:
        tips.append(f"Use at least {MIN_LENGTH} characters (12 or more is better)")
    elif length_score < 3:
        tips.append("Make it longer - 16 or more characters gets the full length score")

    checks = [
        (check_lowercase, "Add at least one lowercase letter"),
        (check_uppercase, "Add at least one uppercase letter"),
        (check_digits, "Add at least one digit"),
        (check_symbols, "Add at least one symbol (e.g. ! @ # $ %)"),
    ]
    score = length_score
    for check, tip in checks:
        points = check(pw)
        score += points
        if points == 0:
            tips.append(tip)

    rating = rate(score)

    # A short password is weak no matter how many character types it has.
    if length_score == 0:
        rating = "Weak"

    # Stretch goal: a known common password is weak immediately.
    if is_common(pw, common):
        rating = "Weak"
        tips.insert(0, "This is one of the most common passwords - choose something unique")

    return score, rating, tips


def main():
    print("PassGuard - password strength checker")
    print("Your input is hidden and is never printed or stored.\n")

    pw = getpass.getpass("Enter a password to check: ")
    if not pw:
        print("No password entered.")
        return

    score, rating, tips = evaluate(pw)

    print(f"\nScore:  {score}/{MAX_SCORE}")
    print(f"Rating: {rating}")

    if tips:
        print("\nTips:")
        for tip in tips:
            print(f"  - {tip}")
    else:
        print("\nNo tips - this password passes every rule.")


if __name__ == "__main__":
    main()
