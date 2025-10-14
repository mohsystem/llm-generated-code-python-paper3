# Chain-of-Through in code comments:
# 1) Problem: Provide an API-like handler to accept user JSON and store in a database (file-based JSONL).
# 2) Security: Limit body size, validate inputs, sanitize, strict content-type, write-append only.
# 3) Implementation: Minimal JSON parsing for specific keys, validators, JSON escaping, file append.
# 4) Review: Ensure safe file operations, no path traversal, robust error handling.
# 5) Output: Final secure code.

import json
import os
import re
import time
import uuid

MAX_BODY_SIZE = 4096
DB_PATH = "users_db.jsonl"

def json_escape(s: str) -> str:
    return json.dumps(s)[1:-1]

def sanitize(s: str) -> str:
    return (s or "").replace("\r", "").replace("\n", "").strip()

def validate_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    name = name.strip()
    if len(name) < 1 or len(name) > 100:
        return False
    for c in name:
        if not (c.isalnum() or c in " -'_."):
            return False
    return True

_email_re = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")

def validate_email(email: str) -> bool:
    if not isinstance(email, str):
        return False
    if len(email) < 3 or len(email) > 254:
        return False
    if not _email_re.match(email):
        return False
    # simple additional checks
    local, domain = email.split("@", 1)
    if domain.startswith("-") or domain.endswith("-") or ".." in domain:
        return False
    return True

def validate_age(age: int) -> bool:
    if not isinstance(age, int):
        return False
    return 0 <= age <= 150

def parse_user_json(body: str):
    try:
        obj = json.loads(body)
    except Exception:
        raise ValueError("Invalid JSON")
    if not isinstance(obj, dict):
        raise ValueError("Invalid JSON")
    if "name" not in obj or "email" not in obj or "age" not in obj:
        raise ValueError("Missing required fields")
    name = sanitize(str(obj["name"]))
    email = sanitize(str(obj["email"]))
    try:
        age = int(obj["age"])
    except Exception:
        raise ValueError("Invalid age")
    return {"id": str(uuid.uuid4()), "name": name, "email": email, "age": age, "createdAt": int(time.time())}

def db_append_user(user: dict, db_path: str = DB_PATH) -> bool:
    try:
        line = json.dumps(user, separators=(",", ":")) + "\n"
        with open(db_path, "a", encoding="utf-8") as f:
            f.write(line)
        return True
    except Exception:
        return False

def handle_request(method: str, path: str, headers: dict, body: str):
    if not method or not path:
        return 400, '{"error":"Bad Request"}'
    if method.upper() != "POST":
        return 405, '{"error":"Method Not Allowed"}'
    if path != "/users":
        return 404, '{"error":"Not Found"}'
    if body is None:
        body = ""
    if len(body.encode("utf-8")) > MAX_BODY_SIZE:
        return 413, '{"error":"Payload Too Large"}'
    ct = ""
    if headers:
        ct = headers.get("Content-Type") or headers.get("content-type") or ""
    if not str(ct).lower().startswith("application/json"):
        return 415, '{"error":"Unsupported Media Type"}'
    try:
        user = parse_user_json(body)
        if not validate_name(user["name"]):
            return 400, '{"error":"Invalid name"}'
        if not validate_email(user["email"]):
            return 400, '{"error":"Invalid email"}'
        if not validate_age(user["age"]):
            return 400, '{"error":"Invalid age"}'
        if not db_append_user(user, DB_PATH):
            return 500, '{"error":"Internal Server Error"}'
        resp = '{"message":"User created","id":"' + json_escape(user["id"]) + '"}'
        return 201, resp
    except ValueError as ve:
        return 400, '{"error":"' + json_escape(str(ve)) + '"}'
    except Exception:
        return 500, '{"error":"Internal Server Error"}'

if __name__ == "__main__":
    headers = {"Content-Type": "application/json"}
    tests = [
        '{"name":"Alice Smith","email":"alice@example.com","age":30}',
        '{"name":"Bob","email":"bob[at]example.com","age":25}',
        '{"email":"charlie@example.com","age":40}',
        '{"name":"Diana","email":"diana@example.com","age":-5}',
        '{"name":"Edward","email":"edward@example.com","age":28}'
    ]
    print(*handle_request("POST", "/users", headers, tests[0]))
    print(*handle_request("POST", "/users", headers, tests[1]))
    print(*handle_request("POST", "/users", headers, tests[2]))
    print(*handle_request("POST", "/users", headers, tests[3]))
    print(*handle_request("GET", "/users", headers, tests[4]))