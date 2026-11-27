# PassGuard - Password Strength & Breach Checker

A command-line Python tool that scores a password, rates it **Weak**, **Medium** or **Strong**, estimates its entropy, detects predictable patterns, checks for known data breaches using **k-anonymity**, and prints specific tips for every problem it finds.

- Week 1: length and character-variety rules, hidden input, tips
- Week 2: entropy estimate, common-password and pattern detection, time-to-guess estimate, pytest tests
- Week 3: privacy-preserving breach check via Have I Been Pwned (HIBP) range API using SHA-1 & k-anonymity, prefix response caching, and offline error handling

## Legal and ethical note

Scanning or attacking systems you do not own, or do not have written permission to test, is illegal. PassGuard never sends your password over the network. The breach check uses **k-anonymity**: only the first 5 characters of the password's SHA-1 hash are sent to the Have I Been Pwned API. Your password and remaining hash suffix never leave your machine. Test with sample passwords, never your real ones.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python passguard.py
```

Dependencies: `requests` for the range API query and `pytest` for the test suite.

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
Breach:  Found in 3,856,123 known data breaches!

Patterns found:
  - common word
  - year

Tips:
  - Found in 3,856,123 known data breaches - do not use this password
  - Avoid common words - use something unpredictable
  - Avoid years such as a birth year or the current year
  - Make it longer - 16 or more characters gets the full length score
```

The password is read with `getpass.getpass()`, so nothing appears on screen while typing. The tool never prints or logs the raw password or its full hash.

## How the breach check works (k-Anonymity)

1. **SHA-1 Hashing**: The password is hashed using SHA-1 (`hashlib.sha1(pw.encode()).hexdigest().upper()`).
2. **Hash Splitting**: The 40-character hex hash is divided into:
   - **Prefix (first 5 characters)**: e.g., `5BAA6`
   - **Suffix (remaining 35 characters)**: e.g., `1E4C9B93F3F0682250B6CF8331B7EE68FD8`
3. **Range Query**: Only the 5-character prefix is sent to the Have I Been Pwned endpoint:
   `https://api.pwnedpasswords.com/range/5BAA6`
4. **k-Anonymity**: The API returns all known hash suffixes starting with that prefix along with their breach counts (typically hundreds or thousands of hashes). The server never learns which suffix belongs to the user.
5. **Local Matching**: PassGuard checks locally whether the suffix appears in the returned list. If found, the breach count is extracted.
6. **Network Error Handling**: All network requests are wrapped with timeouts and error handling. If the machine is offline or the API is unreachable, the tool gracefully displays an offline notice without crashing.
7. **Prefix Caching**: Responses are cached locally in memory so repeated queries for passwords sharing the same prefix do not trigger duplicate network requests.

## How the score works

Base score (from week 1):

| Rule | Points |
|------|--------|
| Length 8-11 / 12-15 / 16+ | 1 / 2 / 3 |
| Has a lowercase letter | 1 |
| Has an uppercase letter | 1 |
| Has a digit | 1 |
| Has a symbol | 1 |

Pattern penalties (from week 2). Each kind of pattern found removes 2 points:

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

Overrides that force **Weak**:
- Password is shorter than 8 characters
- Password appears in `common.txt` (case-insensitive match)
- Password is confirmed in known data breaches (breach count > 0)

## Sample results

| Sample password | Score | Rating | Entropy | Breach Status | Notes |
|-----------------|-------|--------|---------|---------------|-------|
| `abc123` | 2/7 | Weak | 31.0 bits | Breached (>1M) | common password |
| `Sunny-Day7` | 5/7 | Medium | 65.5 bits | Safe (0) | |
| `Tr4il-Mix&Coffee-92!` | 7/7 | Strong | 131.1 bits | Safe (0) | |
| `P@ssw0rd123!` | 6/7 | Weak | 78.7 bits | Breached (>10k) | common password & breached |
| `Password2024!` | 2/7 | Weak | 85.2 bits | Breached (>3M) | common word & year, breached |

## Tests

```bash
pytest -v
```

All 32 tests run completely offline and finish in under a fraction of a second. Network calls are mocked using `unittest.mock.patch` to verify:
- Hash prefix/suffix splitting for k-anonymity
- Only the 5-character prefix is sent over the network
- Breached detection and count reporting
- Safe (unbreached) detection
- Graceful error handling during timeouts and network drops
- Prefix response caching
- Entropy formula, pattern detection, and password confidentiality

## Files

- `passguard.py` - main tool: rules, entropy, pattern detection, k-anonymity breach check, and reporting
- `test_passguard.py` - pytest test suite with mocked network calls
- `common.txt` - common passwords & word list
- `requirements.txt` - project dependencies (`requests`, `pytest`)

## What I learned

- **k-Anonymity**: How to query a public threat database without disclosing private user credentials.
- **SHA-1 Range API**: Dividing cryptographic digests into public prefixes and private local suffixes.
- **Resilience**: Designing tools to fail open or gracefully display offline state without crashing.
- **Testing Network Interactions**: Using `unittest.mock.patch` to simulate API responses, errors, and timeouts.
- **Caching**: Avoiding redundant network round-trips by caching prefix results.
