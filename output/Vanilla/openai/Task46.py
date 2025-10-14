import os
import csv
import re

DB_FILE = "users_python.csv"
HEADER = ["name", "email", "password"]
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

def init_db():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(HEADER)

def sanitize(s: str) -> str:
    if s is None:
        return ""
    return s.replace("\n", " ").replace("\r", " ").replace(",", " ").strip()

def email_exists(email: str) -> bool:
    init_db()
    with open(DB_FILE, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("email", "").lower() == email.lower():
                return True
    return False

def register_user(name: str, email: str, password: str) -> bool:
    init_db()
    name = sanitize(name)
    email = sanitize(email)
    password = sanitize(password)

    if not name or not email or not password:
        return False
    if not EMAIL_RE.match(email):
        return False
    if len(password) < 6:
        return False
    if email_exists(email):
        return False

    with open(DB_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([name, email, password])
    return True

def get_all_users():
    init_db()
    users = []
    with open(DB_FILE, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            users.append({"name": row.get("name", ""), "email": row.get("email", ""), "password": row.get("password", "")})
    return users

if __name__ == "__main__":
    print("Test 1 (valid):", register_user("Alice", "alice@example.com", "pass123"))
    print("Test 2 (duplicate email):", register_user("Alicia", "alice@example.com", "differentPass"))
    print("Test 3 (invalid email):", register_user("Bob", "bob_at_example.com", "secret12"))
    print("Test 4 (short password):", register_user("Charlie", "charlie@example.com", "123"))
    print("Test 5 (valid):", register_user("Dana", "dana@example.org", "StrongPass9"))

    print("All users:")
    for u in get_all_users():
        print(u)