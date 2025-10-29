🔐 Password Strength Analyzer



A simple Python tool that evaluates the strength of a password and provides feedback to help users improve their security practices.

This project demonstrates fundamental cybersecurity concepts like password complexity, hashing, and risk mitigation — inspired by lessons from the Google Cybersecurity Professional Certificate.



🧠 Features



✅ Evaluates password strength based on:



Length and character diversity



Use of uppercase, lowercase, numbers, and special symbols



Detection of weak/common patterns



🔢 Calculates a strength score (Weak / Medium / Strong)



🧱 Hashes the password using SHA-256 for secure representation



🧩 Provides improvement suggestions for weak passwords



⚙️ How It Works



The user inputs a password (hidden for privacy).



The script analyzes the password for common vulnerabilities.



A score and security feedback are displayed.



The password is hashed and optionally stored or compared.



🚀 Usage

Prerequisites



Python 3.x



No external dependencies required.



Run the Script

python3 password\_analyzer.py



Example Output

Enter your password: \*\*\*\*\*\*\*\*\*



Password Strength: Medium (65/100)

Feedback:

\- Add more special characters.

\- Increase length beyond 12 characters.



SHA-256 Hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08



🧩 File Structure

password-strength-analyzer/

├── password\_analyzer.py

├── README.md

└── sample\_output.txt



📘 Learning Outcomes



Understanding password complexity and entropy



Hands-on practice with hashing algorithms (hashlib)



Building a simple CLI security utility



Reinforcing cybersecurity fundamentals through applied coding



🧠 Future Improvements



Add password entropy calculation



Create a Flask web interface



Integrate with a database to track reused or leaked passwords



🏷️ License



MIT License



👨‍💻 Author



Richeek Basu

B.S. Computer Science – CSUSM

LinkedIn

&nbsp;• GitHub

