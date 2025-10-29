import re
import hashlib
import getpass

# --------------------------------------------
# Password Strength Analyzer
# --------------------------------------------
# Evaluates password strength based on:
# length, character diversity, and common patterns.
# Also provides SHA-256 hash for secure representation.
# --------------------------------------------

def evaluate_password_strength(password):
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 30
    elif len(password) >= 8:
        score += 20
        feedback.append("Increase length beyond 12 characters for stronger protection.")
    else:
        score += 10
        feedback.append("Password is too short (minimum 8 characters recommended).")

    # Character variety checks
    if re.search(r"[A-Z]", password):
        score += 15
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 15
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"[0-9]", password):
        score += 15
    else:
        feedback.append("Add numbers to improve complexity.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
    else:
        feedback.append("Add special characters (e.g., !@#$%).")

    # Common pattern check
    common_patterns = ["password", "123", "qwerty", "letmein", "admin"]
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 20
        feedback.append("Avoid common patterns like 'password' or '123'.")

    # Normalize score
    score = max(0, min(score, 100))

    # Strength label
    if score < 40:
        strength = "Weak"
    elif score < 70:
        strength = "Medium"
    else:
        strength = "Strong"

    return score, strength, feedback


def hash_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed


def main():
    print("\n Password Strength Analyzer ")
    password = getpass.getpass("Enter your password: ")

    score, strength, feedback = evaluate_password_strength(password)
    hashed = hash_password(password)

    print(f"\nPassword Strength: {strength} ({score}/100)")
    print("\nFeedback:")
    for item in feedback:
        print(f"- {item}")

    print(f"\nSHA-256 Hash: {hashed}")


if __name__ == "__main__":
    main()
