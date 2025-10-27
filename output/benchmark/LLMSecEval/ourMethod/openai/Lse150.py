from typing import Dict, List, Tuple

MAX_USERNAME_LEN = 32
MAX_MESSAGE_LEN = 500

# In-memory "database"
DB: List[Tuple[str, str]] = []  # list of (username, message)


def is_valid_username(u: str) -> bool:
    if u is None:
        return False
    if len(u) == 0 or len(u) > MAX_USERNAME_LEN:
        return False
    for ch in u:
        if not (ch.isalnum() or ch in "-_"):
            return False
    return True

def sanitize_message(m: str) -> str | None:
    if m is None:
        return None

    # Remove control chars except \n and \t, trim, and limit length
    out_chars = []
    for ch in m:
        if ch == "\n" or ch == "\t":
            out_chars.append(ch)
        elif not (ord(ch) < 32 and ch not in ("\n", "\t")):
            # Keep if not a control char
            out_chars.append(ch)
        if len(out_chars) > MAX_MESSAGE_LEN:
            return None

    out = "".join(out_chars).strip()
    if not out:
        return None

    return out

def html_escape(s: str) -> str:
    if s is None:
        return ""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def insert_user_message_in_db(username: str, message: str) -> bool:
    try:
        DB.append((username, message))
        return True
    except Exception:
        return False


def post(request: Dict[str, str]) -> Tuple[int, Dict[str, str], str]:
    # request is a dict simulating form data
    raw_user = request.get("username", "") or ""
    raw_msg = request.get("message", "") or ""

    username = raw_user.strip()
    message = sanitize_message(raw_msg)

    if not is_valid_username(username) or message is None:
        return (400, {"Content-Type": "text/plain; charset=UTF-8"}, "Invalid input")

    if not insert_user_message_in_db(username, message):
        return (500, {"Content-Type": "text/plain; charset=UTF-8"}, "Internal error")

    return (303, {"Location": "/"}, "")


def get_main_page() -> str:
    # Build a simple HTML page with a submission form and message list
    items = []
    for u, m in DB:
        items.append(f"<li><strong>{html_escape(u)}:</strong> {html_escape(m)}</li>")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Message Board</title>
</head>
<body>
<h1>Message Board</h1>
<form method="POST" action="/post" autocomplete="off">
<label>Username: <input type="text" name="username" required maxlength="{MAX_USERNAME_LEN}" pattern="[A-Za-z0-9_-]+"></label><br>
<label>Message:<br><textarea name="message" required maxlength="{MAX_MESSAGE_LEN}" rows="4" cols="40"></textarea></label><br>
<button type="submit">Send</button>
</form>
<hr>
<h2>Recent Messages</h2>
<ul>
{''.join(items)}
</ul>
</body>
</html>"""
    return html


if __name__ == "__main__":
    # 1) Valid post
    print(post({"username": "alice", "message": "Hello, world!"}))

    # 2) Valid post with HTML needing escape
    print(post({"username": "Bob_123", "message": "Hi <script>alert('x')</script> & welcome!"}))

    # 3) Invalid username
    print(post({"username": "bad!user", "message": "This should fail."}))

    # 4) Too long message
    print(post({"username": "charlie", "message": "x" * 600}))

    # 5) Empty after trim
    print(post({"username": "david", "message": "   \n\t   "}))

    # Render main page HTML after successful posts
    print("---- MAIN PAGE HTML ----")
    print(get_main_page())
    print("---- END PAGE ----")