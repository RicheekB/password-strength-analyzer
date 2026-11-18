"""Password Strength Analyzer

Scores a password on length, character variety and common-pattern use, and
estimates its entropy. Optionally shows how a password should be stored:
salted and hashed with scrypt (standard library, no extra dependencies).

Note: a plain, unsalted SHA-256 hash is NOT safe for storing passwords.
It is fast, so attackers can test billions of guesses per second, and with no
salt identical passwords produce identical hashes. Use a slow, salted
algorithm such as scrypt, bcrypt or argon2.
"""

import argparse
import getpass
import hashlib
import hmac
import math
import os
import re

# Tiny sample list. For real use, check against a large breached-password
# list (e.g. rockyou or Have I Been Pwned).
COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "123456789", "qwerty",
    "abc123", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon",
}
COMMON_PATTERNS = ("password", "123", "qwerty", "letmein", "admin", "welcome", "iloveyou")

# scrypt cost parameters (memory use is about 128 * N * r bytes = 16 MiB)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
SALT_BYTES = 16
KEY_BYTES = 32


def estimate_entropy(password):
    """Rough upper-bound entropy in bits: length * log2(character pool size)."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    return len(password) * math.log2(pool) if pool else 0.0


def evaluate_password_strength(password):
    """Return (score 0-100, label, feedback list)."""
    feedback = []

    if password.lower() in COMMON_PASSWORDS:
        return 0, "Weak", ["This is one of the most commonly used passwords."]

    score = 0

    # Length (max 40)
    if len(password) >= 16:
        score += 40
    elif len(password) >= 12:
        score += 30
        feedback.append("Use 16+ characters for stronger protection.")
    elif len(password) >= 8:
        score += 20
        feedback.append("Use 12+ characters; length matters most.")
    else:
        score += 10
        feedback.append("Too short (minimum 8 characters recommended).")

    # Character variety (15 each, max 60)
    checks = (
        (r"[A-Z]", "Add uppercase letters."),
        (r"[a-z]", "Add lowercase letters."),
        (r"[0-9]", "Add numbers."),
        (r"[^A-Za-z0-9]", "Add special characters (e.g., !@#$%)."),
    )
    for pattern, advice in checks:
        if re.search(pattern, password):
            score += 15
        else:
            feedback.append(advice)

    # Penalties
    lowered = password.lower()
    if any(p in lowered for p in COMMON_PATTERNS):
        score -= 20
        feedback.append("Avoid common patterns like 'password' or '123'.")
    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Avoid repeating the same character 3+ times in a row.")

    score = max(0, min(score, 100))

    # Variety can't make up for a short password: cap the score by length.
    if len(password) < 8:
        score = min(score, 39)
    elif len(password) < 12:
        score = min(score, 69)

    if score < 40:
        label = "Weak"
    elif score < 70:
        label = "Medium"
    else:
        label = "Strong"

    return score, label, feedback


def hash_password(password, salt=None):
    """Salted scrypt hash, returned as 'scrypt$N$r$p$salt_hex$hash_hex'."""
    salt = salt if salt is not None else os.urandom(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_BYTES,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    """Check a password against a stored hash, in constant time."""
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        candidate = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p), dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument(
        "--hash", action="store_true",
        help="also show a salted scrypt hash (demonstrates safe storage)",
    )
    args = parser.parse_args()

    print("\n Password Strength Analyzer ")
    password = getpass.getpass("Enter your password: ")

    score, label, feedback = evaluate_password_strength(password)
    print(f"\nPassword Strength: {label} ({score}/100)")
    print(f"Estimated entropy: {estimate_entropy(password):.0f} bits")

    if feedback:
        print("\nFeedback:")
        for item in feedback:
            print(f"- {item}")

    if args.hash:
        stored = hash_password(password)
        print(f"\nSalted scrypt hash: {stored}")
        print(f"Verifies correctly: {verify_password(password, stored)}")


if __name__ == "__main__":
    main()
