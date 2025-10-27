import html
import re
import time

MAX_MESSAGE_LEN = 500
MAX_USERNAME_LEN = 32
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{1,32}$')

_DB = []

def sanitize_username(username: str):
    if username is None:
        return None
    u = username.strip()
    if not u or len(u) > MAX_USERNAME_LEN:
        return None
    if not USERNAME_RE.match(u):
        return None
    return u

def sanitize_message(message: str):
    if message is None:
        return None
    m = message.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not m:
        return None
    if len(m) > MAX_MESSAGE_LEN:
        m = m[:MAX_MESSAGE_LEN]
    # Remove control chars except tab/newline
    m = "".join(ch for ch in m if ch == '\n' or ch == '\t' or (ord(ch) >= 0x20 and ord(ch) != 0x7F))
    return m

def insert_user_message_in_db(username: str, message: str):
    _DB.append({
        "username": username,
        "message": message,
        "ts": int(time.time())
    })

def post(username: str, message: str) -> str:
    u = sanitize_username(username)
    m = sanitize_message(message)
    if u is not None and m is not None:
        insert_user_message_in_db(u, m)
    return "redirect:/"

def display_messages() -> str:
    parts = ["<html><body>", "<h2>Messages</h2>", "<ul>"]
    for row in _DB:
        parts.append(
            "<li><strong>{}:</strong> {}</li>".format(
                html.escape(row["username"], quote=True),
                html.escape(row["message"], quote=True)
            )
        )
    parts.append("</ul></body></html>")
    return "\n".join(parts)

def render_main_page() -> str:
    return display_messages()

def main():
    # 5 test cases
    print(post("alice", "Hello, world!"))
    print(post("bob_42", "This is a test message."))
    print(post("charlie", "<script>alert('xss');</script> Stay safe!"))
    print(post("invalid name", "Should be rejected due to invalid username."))
    print(post("david", ""))  # empty message rejected

    print(render_main_page())

if __name__ == "__main__":
    main()