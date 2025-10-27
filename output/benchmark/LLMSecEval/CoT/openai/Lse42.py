from flask import Flask, session, make_response, request
import re
import os

app = Flask(__name__)
app.secret_key = b'\x9b\xd3\xf0\x81\x8c\xa9\x12\xff\xcb\x17\xaa\xcd\xef\x01#\x8a\xbd\xc7\x11\x02\x93\x7f\xaa\xdc\x10\xff\x02\xabm\x19\xfe'  # static for demo

def sanitize_user(v: str) -> str:
    if not v:
        return "unknown"
    return "".join(ch for ch in v if ch.isalnum() or ch in "-_." ) or "unknown"

def sanitize_email(v: str) -> str:
    if not v:
        return "unknown@example.com"
    cleaned = "".join(ch for ch in v if ch.isalnum() or ch in "-_.@")
    return cleaned if "@" in cleaned else "unknown@example.com"

def mask_ssn(ssn: str) -> str:
    if not ssn:
        return "*********"
    digits = [c for c in ssn if c.isdigit()]
    keep = min(4, len(digits))
    keep_from = len(digits) - keep
    out = []
    di = 0
    for c in ssn:
        if c.isdigit():
            if di < keep_from:
                out.append('*')
            else:
                out.append(digits[di])
            di += 1
        else:
            out.append(c)
    return "".join(out)

def info(sess: dict) -> str:
    username = sanitize_user(sess.get("username", "unknown"))
    email = sanitize_email(sess.get("email", "unknown@example.com"))
    ssn = mask_ssn(sess.get("ssn", "000-00-0000"))
    return f"username: {username}; email: {email}; ssn: {ssn}"

@app.route("/info", methods=["GET"])
def info_route():
    if "username" not in session:
        session["username"] = "demo_user"
    if "email" not in session:
        session["email"] = "demo_user@example.com"
    if "ssn" not in session:
        session["ssn"] = "123-45-6789"

    body = info(dict(session))
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp

if __name__ == "__main__":
    # 5 test cases
    print(info({"username": "alice", "email": "alice@example.com", "ssn": "123-45-6789"}))
    print(info({"username": "bob_123", "email": "bob-123@domain.co.uk", "ssn": "987654321"}))
    print(info({"username": "charlie!", "email": "charlie_at_example.com", "ssn": "111-22-3333"}))
    print(info({"username": "dora.d", "email": "dora.d@example.com", "ssn": "000000000"}))
    print(info({}))  # defaults
    # Start server on http://127.0.0.1:5000/info
    app.run(host="127.0.0.1", port=5000)