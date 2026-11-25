# PassGuard - Week 1: Password Strength Rules

A small command-line Python tool that scores a password, rates it **Weak**, **Medium** or **Strong**, and prints a specific tip for every rule it fails.

## Legal and ethical note

Scanning or attacking systems you do not own, or do not have written permission to test, is illegal. This project does not touch any network or any other system: it runs only on your own machine and only checks text you type into it. Test it with sample passwords, never your real ones.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
python passguard.py
```

No third-party packages are needed - only the Python standard library.

## Usage

```
$ python passguard.py
PassGuard - password strength checker
Your input is hidden and is never printed or stored.

Enter a password to check:

Score:  2/7
Rating: Weak

Tips:
  - This is one of the most common passwords - choose something unique
  - Use at least 8 characters (12 or more is better)
  - Add at least one uppercase letter
  - Add at least one symbol (e.g. ! @ # $ %)
```

The password is read with `getpass.getpass()`, so nothing appears on screen while you type. The tool never prints or saves the password - only the score and the tips.

## How the score works

| Rule | Points |
|------|--------|
| Length 8-11 / 12-15 / 16+ | 1 / 2 / 3 |
| Has a lowercase letter | 1 |
| Has an uppercase letter | 1 |
| Has a digit | 1 |
| Has a symbol | 1 |

| Total | Rating |
|-------|--------|
| 0-3 | Weak |
| 4-5 | Medium |
| 6-7 | Strong |

Two overrides always force **Weak**:

- the password is shorter than 8 characters, whatever else it contains
- the password appears in `common_passwords.txt` (case-insensitive match)

## Sample results

| Sample password | Score | Rating |
|-----------------|-------|--------|
| `abc123` | 2/7 | Weak |
| `Sunny-Day7` | 5/7 | Medium |
| `Tr4il-Mix&Coffee-92!` | 7/7 | Strong |
| `P@ssw0rd123!` | 6/7 | Weak (common password) |

## Files

- `passguard.py` - the tool; each rule is its own small function (`check_length`, `check_lowercase`, `check_uppercase`, `check_digits`, `check_symbols`)
- `common_passwords.txt` - small list of very common passwords, one per line; add more lines to extend it

## What I learned

- Length matters more than anything else, so it carries the most points
- Character variety helps, but a predictable password is weak even when it passes every variety rule
- `getpass` keeps secrets off the screen, and a security tool should never echo or log the secret it checks

## Further reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
