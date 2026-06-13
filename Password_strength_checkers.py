import re
import math
import random
import string
import hashlib
import sqlite3

# -----------------------------
# DATABASE SETUP
# -----------------------------
conn = sqlite3.connect("password_history.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT UNIQUE
)
""")
conn.commit()


# -----------------------------
# HASH PASSWORD
# -----------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# -----------------------------
# CHECK PASSWORD REUSE
# -----------------------------
def is_reused(password):
    password_hash = hash_password(password)

    cursor.execute(
        "SELECT * FROM password_history WHERE password_hash=?",
        (password_hash,)
    )

    return cursor.fetchone() is not None


# -----------------------------
# SAVE PASSWORD HASH
# -----------------------------
def save_password(password):
    password_hash = hash_password(password)

    try:
        cursor.execute(
            "INSERT INTO password_history(password_hash) VALUES(?)",
            (password_hash,)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass


# -----------------------------
# COMMON PASSWORD CHECK
# -----------------------------
common_passwords = {
    "password",
    "123456",
    "123456789",
    "qwerty",
    "admin",
    "welcome",
    "abc123",
    "password123"
}


# -----------------------------
# ENTROPY CALCULATION
# -----------------------------
def calculate_entropy(password):

    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26

    if re.search(r"[A-Z]", password):
        charset_size += 26

    if re.search(r"\d", password):
        charset_size += 10

    if re.search(r"[^A-Za-z0-9]", password):
        charset_size += 32

    if charset_size == 0:
        return 0

    entropy = len(password) * math.log2(charset_size)

    return round(entropy, 2)


# -----------------------------
# PASSWORD SUGGESTION
# -----------------------------
def generate_strong_password(length=16):

    characters = (
        string.ascii_uppercase +
        string.ascii_lowercase +
        string.digits +
        "!@#$%^&*"
    )

    while True:
        password = ''.join(
            random.choice(characters)
            for _ in range(length)
        )

        if (
            re.search(r"[A-Z]", password)
            and re.search(r"[a-z]", password)
            and re.search(r"\d", password)
            and re.search(r"[!@#$%^&*]", password)
        ):
            return password


# -----------------------------
# PASSWORD ANALYZER
# -----------------------------
def analyze_password(password):

    score = 0
    feedback = []

    # Length Check
    length = len(password)

    if length < 8:
        feedback.append("Password is too short.")
    elif length >= 8:
        score += 1

    if length >= 12:
        score += 1

    if length >= 16:
        score += 1

    # Complexity Checks
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add special characters.")

    # Common Password Check
    if password.lower() in common_passwords:
        feedback.append("This is a common password.")
        score = max(score - 3, 0)

    # Reuse Check
    reused = is_reused(password)

    if reused:
        feedback.append("Password has been used before.")
        score = max(score - 2, 0)

    entropy = calculate_entropy(password)

    # Strength Rating
    if score <= 3:
        strength = "Weak"
    elif score <= 6:
        strength = "Medium"
    elif score <= 8:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return {
        "strength": strength,
        "score": score,
        "entropy": entropy,
        "feedback": feedback,
        "reused": reused
    }


# -----------------------------
# MAIN PROGRAM
# -----------------------------
def main():

    print("=" * 50)
    print("PASSWORD STRENGTH ANALYZER")
    print("=" * 50)

    password = input("Enter Password: ")

    result = analyze_password(password)

    print("\n----- RESULT -----")
    print("Strength :", result["strength"])
    print("Score    :", result["score"], "/ 10")
    print("Entropy  :", result["entropy"], "bits")

    if result["reused"]:
        print("Reuse    : Password already used")

    if result["feedback"]:
        print("\nSuggestions:")
        for item in result["feedback"]:
            print("-", item)

    print("\nSuggested Strong Password:")
    print(generate_strong_password())

    save_password(password)

    print("\nPassword hash stored securely.")


if __name__ == "__main__":
    main()

    conn.close()
