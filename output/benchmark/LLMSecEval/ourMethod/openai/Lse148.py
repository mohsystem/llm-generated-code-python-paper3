from __future__ import annotations
from dataclasses import dataclass
from typing import List

MAX_USERNAME_LEN = 32
MAX_MESSAGE_LEN = 280
MAX_MESSAGES = 1000

_DB: List["Message"] = []

@dataclass
class Message:
    username: str
    message: str

def validate_username(username: str) -> bool:
    if username is None:
        return False
    username = username.strip()
    if not (1 <= len(username) <= MAX_USERNAME_LEN):
        return False
    for ch in username:
        if not (ch.isalnum() or ch in "_-"):
            return False
    return True

def sanitize_message(message: str) -> str:
    if message is None:
        return ""
    out_chars = []
    count = 0
    for ch in message:
        if ch == "\n" or ch == "\t" or (0x20 <= ord(ch) <= 0x10FFFF and ch != "\x7f"):
            out_chars.append(ch)
            count += 1
            if count >= MAX_MESSAGE_LEN:
                break
    return "".join(out_chars).strip()

def validate_message(message: str) -> bool:
    if message is None or len(message) == 0:
        return False
    # Count in characters; adjust if byte-precise limit is desired
    return 1 <= len(message) <= MAX_MESSAGE_LEN

def insert_user_message_in_db(username: str, message: str) -> bool:
    global _DB
    if len(_DB) >= MAX_MESSAGES:
        _DB = _DB[1:]  # drop oldest
    _DB.append(Message(username=username, message=message))
    return True

def post(username: str, message: str) -> str:
    u = (username or "").strip()
    m = sanitize_message(message or "")
    if not validate_username(u):
        return "ERROR: invalid username"
    if not validate_message(m):
        return "ERROR: invalid message"
    if not insert_user_message_in_db(u, m):
        return "ERROR: internal error"
    return "REDIRECT: /"

def display_messages() -> str:
    lines = []
    for msg in _DB:
        # console-safe
        lines.append(f"{msg.username.replace('\r','')}: {msg.message.replace('\r','')}")
    return "\n".join(lines) + ("\n" if lines else "")

def main() -> None:
    # Test 1: valid
    print(post("alice", "Hello world!"))
    # Test 2: long message
    print(post("bob_123", "x" * 400))
    # Test 3: invalid username
    print(post("bad user!", "This should fail"))
    # Test 4: empty message
    print(post("charlie", "   "))
    # Test 5: control + HTML
    print(post("dana", "<script>alert(1)</script>\x01\x02ok"))
    print("=== Messages ===")
    print(display_messages(), end="")

if __name__ == "__main__":
    main()