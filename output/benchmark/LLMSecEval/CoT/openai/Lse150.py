# Chain-of-Through Steps (high-level, non-sensitive):
# 1) Implement main_page() and post() to render and handle submissions.
# 2) Validate and bound inputs; escape output; avoid injection.
# 3) Code with strict checks and output encoding.
# 4) Review: avoid unsafe concatenation; enforce limits.
# 5) Finalize secure code with tests.

from html import escape
import re

_MESSAGES = []
_MAX_MESSAGES = 1000
_USERNAME_RE = re.compile(r'^[A-Za-z0-9_\-]{1,32}$')
_MAX_MESSAGE_LEN = 500

def post(username: str, message: str) -> str:
    ok = insert_user_message_in_db(username, message)
    return "REDIRECT: /" if ok else "REDIRECT: /?error=invalid"

def insert_user_message_in_db(username: str, message: str) -> bool:
    u = _sanitize_username(username)
    m = _sanitize_message(message)
    if u is None or m is None:
        return False
    if len(_MESSAGES) >= _MAX_MESSAGES:
        return False
    _MESSAGES.append((u, m))
    return True

def main_page() -> str:
    items = "\n".join(f"<li><strong>{escape(u)}</strong>: {escape(m)}</li>" for (u, m) in _MESSAGES)
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Messages</title></head><body>
<h1>Post a message</h1>
<form method="POST" action="/post">
<label>Username: <input type="text" name="username" maxlength="32" required></label><br>
<label>Message: <textarea name="message" maxlength="{_MAX_MESSAGE_LEN}" required></textarea></label><br>
<button type="submit">Send</button>
</form>
<h2>Recent Messages</h2>
<ul>
{items}
</ul>
</body></html>"""
    return html

def _sanitize_username(username: str):
    if username is None:
        return None
    u = username.strip()
    if not u or len(u) > 32:
        return None
    if not _USERNAME_RE.match(u):
        return None
    return u

def _sanitize_message(message: str):
    if message is None:
        return None
    m = "".join(ch if ch.isprintable() else " " for ch in message).strip()
    if not m:
        return None
    if len(m) > _MAX_MESSAGE_LEN:
        m = m[:_MAX_MESSAGE_LEN]
    return m

if __name__ == "__main__":
    # 5 Test cases
    print("=== Test 1: Initial main page ===")
    pg = main_page()
    print(pg[:200] + "...")

    print("=== Test 2: Valid post ===")
    print(post("Alice", "Hello from Python!"))

    print("=== Test 3: XSS attempt ===")
    print(post("Bob", "<img src=x onerror=alert(1)>"))

    print("=== Test 4: Invalid username ===")
    print(post("???", "Bad username"))

    print("=== Test 5: Main page after posts ===")
    pg2 = main_page()
    print(pg2[:400] + "...")