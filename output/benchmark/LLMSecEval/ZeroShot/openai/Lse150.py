import html
import hmac
import os
import secrets
import sys
import unicodedata

# In-memory DB placeholder
MESSAGES_DB = []

def html_escape(s: str) -> str:
    return html.escape(s or "", quote=True)

def validate_username(username: str) -> bool:
    if username is None:
        return False
    u = username.strip()
    if len(u) < 3 or len(u) > 32:
        return False
    for c in u:
        if not (c.isalnum() or c in "_-"):
            return False
    return True

def sanitize_message(message: str):
    if message is None:
        return None
    m = unicodedata.normalize("NFKC", message).strip()
    out_chars = []
    for ch in m:
        if ch == "\n" or (ord(ch) >= 0x20 and ch != "\x7f"):
            out_chars.append(ch)
            if len(out_chars) > 500:
                return None
    if not out_chars:
        return None
    return "".join(out_chars)

def constant_time_equals(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    return hmac.compare_digest(a.encode(), b.encode())

def generate_csrf_token() -> str:
    return secrets.token_hex(32)

def insert_user_message_in_db(username: str, message: str) -> bool:
    # In real impl, use parameterized queries with a DB driver
    MESSAGES_DB.append(f"{username}: {message}")
    return True

def render_main_page(csrf_token: str) -> str:
    safe_token = html_escape(csrf_token)
    return (
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Main</title></head><body>"
        "<h1>Submit a message</h1>"
        "<form method=\"post\" action=\"/post\" autocomplete=\"off\">"
        "<label for=\"username\">Username</label>"
        "<input type=\"text\" id=\"username\" name=\"username\" required minlength=\"3\" maxlength=\"32\" pattern=\"[A-Za-z0-9_\\-]+\">"
        "<br>"
        "<label for=\"message\">Message</label>"
        "<textarea id=\"message\" name=\"message\" required maxlength=\"500\"></textarea>"
        f"<input type=\"hidden\" name=\"csrf\" value=\"{safe_token}\">"
        "<br><button type=\"submit\">Send</button>"
        "</form>"
        "</body></html>"
    )

def post(username: str, message: str, csrf_token_from_request: str, session_csrf_token: str) -> str:
    if not constant_time_equals(csrf_token_from_request, session_csrf_token):
        return "REDIRECT:/?error=csrf"
    if not validate_username(username):
        return "REDIRECT:/?error=bad_username"
    sanitized = sanitize_message(message)
    if sanitized is None:
        return "REDIRECT:/?error=bad_message"
    ok = insert_user_message_in_db(username.strip(), sanitized)
    if not ok:
        return "REDIRECT:/?error=server"
    return "REDIRECT:/"

if __name__ == "__main__":
    session_token = generate_csrf_token()
    print("Rendered Main Page HTML:")
    print(render_main_page(session_token))

    # Test 1: Valid
    print("Test1:", post("alice_01", "Hello world!", session_token, session_token))

    # Test 2: Invalid username
    print("Test2:", post("a", "short name", session_token, session_token))

    # Test 3: Script content
    print("Test3:", post("bob-2", "<script>alert(1)</script>", session_token, session_token))

    # Test 4: Too long message
    long_msg = "x" * 600
    print("Test4:", post("charlie_3", long_msg, session_token, session_token))

    # Test 5: CSRF mismatch
    print("Test5:", post("dave_4", "Valid message", "badtoken", session_token))

    print("DB size:", len(MESSAGES_DB))
    for rec in MESSAGES_DB:
        print(rec)