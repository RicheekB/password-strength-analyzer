Password Strength Analyzer

A Python command-line tool that evaluates the strength of user passwords and provides feedback for improvement.
This project demonstrates core cybersecurity concepts such as password complexity analysis, hashing, and secure coding practices.

Overview

The Password Strength Analyzer checks for:

Password length and character diversity

Use of uppercase, lowercase, digits, and special symbols

Common weak patterns (such as "password", "123", "qwerty")

Secure password hashing using the SHA-256 algorithm

Features

Simple command-line interface

Strength scoring system (Weak, Medium, Strong)

SHA-256 password hashing

Clear feedback to guide password improvement

Installation and Usage

Requirements:

Python 3.8 or higher

To run the script:

python3 password_analyzer.py


Example Output:

Enter your password: *********

Password Strength: Medium (65/100)
Feedback:
- Add more special characters.
- Increase length beyond 12 characters.


SHA-256 Hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08


Project Structure
password-strength-analyzer/
│
├── password_analyzer.py      # Main script
├── README.md                 # Documentation
└── sample_output.txt         # Example output (optional)

Key Learnings

Understanding password strength metrics and entropy

Implementing SHA-256 hashing in Python

Building structured, modular command-line tools

Applying secure programming principles

Future Enhancements

Add password entropy calculation

Develop a simple web interface using Flask

Integrate a leaked-password detection API


Author
Richeek Basu


