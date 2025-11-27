🛡️ BreachGuard - Secure Password Analyzer

Heuristic password strength analysis & k-Anonymity breach detection.

BreachGuard is a cybersecurity tool that analyzes password complexity using local heuristic logic and checks against known data breaches without ever exposing the user's password.

🚀 Features

k-Anonymity Security: Uses SHA-1 hashing and only sends the first 5 characters of the hash to the Have I Been Pwned API. The full password never leaves the client's machine.

Heuristic Analysis: scores passwords based on entropy, length, character sets, and patterns.

Deep Scan: Checks against a database of over 600 million exposed passwords.

Cyberpunk UI: Fully responsive, glassmorphism-based interface with real-time scanning animations.

🛠️ Technology Stack

Backend: Python, Flask

API: HaveIBeenPwned (Range API)

Frontend: HTML5, TailwindCSS, Vanilla JS

Security: SHA-1 Hashing, K-Anonymity model

📦 Installation

Clone the repository:

git clone [https://github.com/YOUR_USERNAME/BreachGuard.git](https://github.com/YOUR_USERNAME/BreachGuard.git)
cd BreachGuard


Create a virtual environment:

# Windows
python -m venv venv
# Mac/Linux
python3 -m venv venv


Activate the environment:

# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate


Install dependencies:

pip install -r requirements.txt


Run the application:

python app.py


🔒 Security Explanation (For Professors/Evaluators)

This tool strictly adheres to privacy-first principles:

Input: User enters password123

Hashing: System converts to SHA-1: CBFDAC6008F9CAB4083784EA22229C5A85DDA33A

Truncation: We split the hash. Prefix: CBFDA, Suffix: C6008...

API Query: We GET https://api.pwnedpasswords.com/range/CBFDA

Local Comparison: The API returns all hashes starting with CBFDA. We loop through them locally to find the matching suffix.

Result: The API service never sees the user's full hash or password.

Created by [Your Name]