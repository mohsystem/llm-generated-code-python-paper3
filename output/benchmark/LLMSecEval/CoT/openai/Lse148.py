# Chain-of-Through (comments):
# 1) Understand: post() extracts username/message, inserts, redirects, display messages.
# 2) Security: validate inputs, length bounds, escape HTML, strip control chars.
# 3) Secure coding: no global mutable exposure, encapsulate, safe defaults.
# 4) Review: avoid printing sensitive data, handle failures with generic redirect.
# 5) Output: final secure functions.

import html
import re
import time
from typing import Dict, List

class _Message:
    __slots__ = ("username_esc", "message_esc", "ts")
    def __init__(self, u: str, m: str, ts: float):
        self.username_esc = u
        self.message_esc = m
        self.ts = ts

# In-memory "DB"
_DB: List[_Message] = []

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,32}$")
_MAX_MESSAGE_LEN = 1000

def _strip_dangerous_controls(s: str) -> str:
    return "".join(ch for ch in s if (ch in "\n\r\t") or (not ch.isascii()) or (not ch.isascii() or not (ord(ch) < 32)) or (ord(ch) >= 32))
    # The above retains printable and whitespace; unnecessary complexity might be confusing.
    # Simpler:
def _strip_dangerous_controls(s: str) -> str:
    return "".join(ch for ch in s if ch in "\n\r\t" or (ord(ch) >= 32))

def insert_user_message_in_db(username: str, message: str) -> bool:
    if username is None or message is None:
        return False
    username = username.strip()
    message = message.strip()
    if not _USERNAME_RE.fullmatch(username):
        return False
    if len(message) == 0 or len(message) > _MAX_MESSAGE_LEN:
        return False
    safe_user = html.escape(username, quote=True)
    safe_msg = html.escape(_strip_dangerous_controls(message), quote=True)
    _DB.append(_Message(safe_user, safe_msg, time.time()))
    return True

def post(request: Dict[str, str]) -> str:
    username = (request.get("username") or "").strip()
    message = (request.get("message") or "").strip()
    ok = insert_user_message_in_db(username, message)
    return "REDIRECT: /" if ok else "REDIRECT: /?error=invalid"

def display_messages() -> str:
    lines = []
    lines.append('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Messages</title></head><body>')
    lines.append('<h1>Messages</h1><ul>')
    for m in list(_DB):
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m.ts))
        lines.append(f"<li><strong>{m.username_esc}</strong> [{ts_str}]: {m.message_esc}</li>")
    lines.append("</ul></body></html>")
    return "".join(lines)

if __name__ == "__main__":
    # 5 test cases
    print(post({"username": "Alice", "message": "Hello world!"}))
    print(post({"username": "Bob_123", "message": "<b>bold</b> & <script>x</script>"}))
    print(post({"username": "Inv@lid", "message": "Nope"}))  # invalid username
    print(post({"username": "Carol", "message": "Line1\nLine2\tTabbed"}))
    print(post({"username": "Dave", "message": "A" * 1005}))  # too long
    print(display_messages())