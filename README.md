# PassGuard - Password Strength Checker

A small command-line Python tool that scores a password, rates it **Weak**, **Medium** or **Strong**, estimates its entropy, detects predictable patterns, and prints a specific tip for every problem it finds.

- Week 1: length and character-variety rules, hidden input, tips
- Week 2: entropy estimate, common-password and pattern detection, time-to-guess estimate, pytest tests

## Legal and ethical note

Scanning or attacking systems you do not own, or do not have written permission to test, is illegal. This project does not touch any network or any other system: it runs only on your own machine and only checks text you type into it. Test it with sample passwords, never your real ones.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python passguard.py
```

The tool itself uses only the Python standard library. `pytest` is needed only to run the tests.

## Usage

```
$ python passguard.py
PassGuard - password strength checker
Your input is hidden and is never printed or stored.

Enter a password to check:

Score:   2/7 (6 before pattern penalties)
Rating:  Weak
Entropy: about 85.2 bits (estimate)
Time to guess: about 71 million years
  at 10,000,000,000 guesses per second, trying every combination
  patterns were found, so a real attacker would be much faster

Patterns found:
  - common word
  - year

Tips:
  - Avoid common words - use something unpredictable
  - Avoid years such as a birth year or the current year
  - Make it longer - 16 or more characters gets the full length score
```

That run used the sample password `Password2024!`. The password is read with `getpass.getpass()`, so nothing appears on screen while you type. The tool never prints or saves the password, and it does not echo the word or year it matched.

## How the score works

Base score (unchanged from week 1):

| Rule | Points |
|------|--------|
| Length 8-11 / 12-15 / 16+ | 1 / 2 / 3 |
| Has a lowercase letter | 1 |
| Has an uppercase letter | 1 |
| Has a digit | 1 |
| Has a symbol | 1 |

Pattern penalties (new in week 2). Each kind of pattern found removes 2 points, so a long password can still drop to Weak:

| Pattern | Example |
|---------|---------|
| Common word inside the password | `password`, `dragon` (case-insensitive) |
| Keyboard sequence | `1234`, `qwer`, `asdf`, `lkjhg` (forwards or backwards) |
| Repeated characters | the same character three or more times in a row |
| Year | any year from 1900 to 2099 |

| Final score | Rating |
|-------------|--------|
| 0-3 | Weak |
| 4-5 | Medium |
| 6-7 | Strong |

Two overrides always force **Weak**:

- the password is shorter than 8 characters, whatever else it contains
- the whole password appears in `common.txt` (case-insensitive match)

## Entropy and time to guess

Entropy is estimated as `length * log2(pool_size)`, where the pool is the set of character types used: 26 lowercase, 26 uppercase, 10 digits, 32 symbols.

The time to guess assumes an attacker trying every combination at 10 billion guesses per second and finding the password halfway through. Both numbers are upper estimates: they assume random characters. A password built from a word and a year is far weaker than its entropy suggests, which is why the tool also checks for patterns and says so when it finds any.

## Sample results

| Sample password | Score | Rating | Entropy | Notes |
|-----------------|-------|--------|---------|-------|
| `abc123` | 2/7 | Weak | 31.0 bits | common password |
| `Sunny-Day7` | 5/7 | Medium | 65.5 bits | |
| `Tr4il-Mix&Coffee-92!` | 7/7 | Strong | 131.1 bits | |
| `P@ssw0rd123!` | 6/7 | Weak | 78.7 bits | common password |
| `Password2024!` | 2/7 | Weak | 85.2 bits | common word and year, 6 before penalties |

The first four are the week 1 examples; their scores and ratings are unchanged.

## Tests

```bash
pytest -v
```

`test_passguard.py` covers weak, medium and strong examples, each pattern detector, the entropy formula, the time description, and a check that the result never contains the password.

## Files

- `passguard.py` - the tool, split into small functions: rule checks, entropy, pattern detectors, `evaluate`, `print_report`
- `test_passguard.py` - pytest tests
- `common.txt` - common passwords, one per line; alphabetic entries also serve as the common-word list. Add more lines to extend it
- `requirements.txt` - test dependency

## What I learned

- Length matters more than anything else, so it carries the most points
- Entropy from the formula is only an estimate; patterns make a password much weaker than it looks
- Pattern detectors need tests for false positives too: "property" contains "erty" from the qwerty row
- `getpass` keeps secrets off the screen, and a security tool should never echo or log the secret it checks

## Further reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
