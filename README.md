# Password Strength Analyzer

A small **Python command-line tool** that scores password strength, estimates entropy, and gives feedback for creating stronger passwords. It also demonstrates how passwords should be *stored*: salted and hashed with scrypt.

Built to apply concepts from the *Google Cybersecurity Professional Certificate*: password entropy, hashing, and risk mitigation.

---

## Overview

The analyzer checks for:
- Password length (longer is better; short passwords can't rate "Strong" however varied they are)
- Character variety: uppercase, lowercase, digits and special symbols
- Common passwords and weak patterns (e.g. `password`, `123`, `qwerty`) and repeated characters
- Estimated entropy in bits
- Optional: a **salted scrypt** hash showing safe password storage

## Why not plain SHA-256?

An earlier version printed a plain SHA-256 hash. That is **not safe for storing passwords**:

- SHA-256 is *fast*, so attackers can try billions of guesses per second.
- With no *salt*, identical passwords give identical hashes, and precomputed (rainbow) tables work.

This version uses `hashlib.scrypt` (standard library) with a random 16-byte salt and a memory-hard cost setting, and verifies with a constant-time comparison. For production systems use a maintained library for bcrypt, scrypt or argon2.

## Usage

Requirements: Python 3.8+ (no external dependencies).

```bash
python3 password_analyzer.py          # score a password
python3 password_analyzer.py --hash   # also show a salted scrypt hash
```

### Example output

```
 Password Strength Analyzer 
Enter your password: ********

Password Strength: Medium (69/100)
Estimated entropy: 72 bits

Feedback:
- Use 12+ characters; length matters most.
```

## Project structure

```
password-strength-analyzer/
├── password_analyzer.py   # Main script
├── README.md              # Documentation
└── sample_output.txt      # Example output
```

## Limitations

- The common-password list is a small sample. Real tools check against large breached-password lists (e.g. Have I Been Pwned).
- Entropy is a rough upper bound; it assumes characters are chosen at random.

## Key learnings

- Password strength depends mostly on length and unpredictability
- Why password storage needs slow, salted hashing, not fast general-purpose hashes
- Safe handling of user input (`getpass`) and constant-time comparison

## Author

Richeek Basu
