import re
from typing import Optional

class Database:
    _instance = None

    def __init__(self) -> None:
        self._emails = {
            "user@example.com",
            "alice@test.com",
            "bob@example.org",
            "newsletter@company.com",
            "sales@shop.co",
        }

    @classmethod
    def connect(cls) -> "Database":
        if cls._instance is None:
            cls._instance = Database()
        return cls._instance

    def remove(self, email_lower: str) -> bool:
        if email_lower in self._emails:
            self._emails.remove(email_lower)
            return True
        return False

MAX_EMAIL_LEN = 254
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

def _sanitize_email(email: Optional[str]) -> Optional[str]:
    if email is None:
        return None
    trimmed = email.strip()
    # Enforce simple ASCII-only emails for this demo
    try:
        trimmed.encode("ascii")
    except UnicodeEncodeError:
        return None
    if not trimmed or len(trimmed) > MAX_EMAIL_LEN:
        return None
    if not EMAIL_RE.fullmatch(trimmed):
        return None
    return trimmed.lower()

def unsubscribe(email: str) -> str:
    normalized = _sanitize_email(email)
    if not normalized:
        return "Invalid email address."
    try:
        db = Database.connect()
        removed = db.remove(normalized)
        return "Unsubscribed successfully." if removed else "Email address not found in database."
    except Exception:
        return "An error occurred."

if __name__ == "__main__":
    tests = [
        "user@example.com",     # should unsubscribe
        "ALICE@test.com",       # unsubscribe (case-insensitive)
        "nobody@nope.com",      # not found
        "bad@@domain..com",     # invalid
        "user@example.com",     # already unsubscribed -> not found
    ]
    for t in tests:
        print(f"Input: {t} -> {unsubscribe(t)}")