import os
import json
import re
import secrets
import time

DB_PATH = "users_db_python.jsonl"

NAME_REGEX = re.compile(r"^[A-Za-z][A-Za-z\s\-']{0,98}[A-Za-z]$")
EMAIL_REGEX = re.compile(r"^(?=.{3,254}$)[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+$")

def is_valid_name(name: str) -> bool:
    if name is None:
        return False
    name = name.strip()
    if len(name) < 2 or len(name) > 100:
        return False    # max 100 chars
    return bool(NAME_REGEX.match(name))

def is_valid_email(email: str) -> bool:
    if email is None:
        return False
    email = email.strip().lower()
    return bool(EMAIL_REGEX.match(email))

def is_valid_age(age: int) -> bool:
    return isinstance(age, int) and 0 <= age <= 150

def escape_json_string(s: str) -> str:
    # json.dumps handles escaping, but we will return the raw string to build the object; prefer safe usage
    return s

def generate_id() -> str:
    return secrets.token_hex(8)

def append_line_to_db(json_line: str) -> None:
    # Append and fsync to reduce risk of data loss
    with open(DB_PATH, "a", encoding="utf-8") as f:
        f.write(json_line)
        f.flush()
        os.fsync(f.fileno())

def create_user(name: str, email: str, age: int) -> str:
    n = (name or "").strip()
    e = (email or "").strip()

    if not is_valid_name(n):
        return "ERROR: invalid name"
    if not is_valid_email(e):
        return "ERROR: invalid email"
    if not is_valid_age(age):
        return "ERROR: invalid age"

    uid = generate_id()
    record = {
        "id": uid,
        "name": n,
        "email": e.lower(),
        "age": age,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        append_line_to_db(line)
        return f"OK: {uid}"
    except Exception:
        return "ERROR: storage failure"

if __name__ == "__main__":
    # 5 test cases
    print(create_user("John Doe", "john.doe@example.com", 30))
    print(create_user("A", "not-an-email", 20))            # invalid
    print(create_user("Mary-Jane O'Neil", "mary@example", -1))  # invalid
    print(create_user("  Robert   ", "robert.smith@example.co.uk", 44))
    print(create_user("ThisNameIsWayTooLong_ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ", "long.name@example.com", 20))