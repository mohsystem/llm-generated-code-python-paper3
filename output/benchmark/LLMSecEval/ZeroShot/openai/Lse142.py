import re

# Simulated database (normalized to lowercase, trimmed)
_DB = set()

_MAX_EMAIL_LENGTH = 254
_MAX_LOCAL_LENGTH = 64

_EMAIL_REGEX = re.compile(r"^[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}$", re.IGNORECASE)

def _normalize(email: str):
    if email is None:
        return None
    s = email.strip()
    if not s or len(s) > _MAX_EMAIL_LENGTH:
        return None
    return s.lower()

def _is_valid_email(email: str) -> bool:
    if email is None or len(email) > _MAX_EMAIL_LENGTH:
        return False
    if not _EMAIL_REGEX.fullmatch(email):
        return False
    at = email.find("@")
    if at <= 0:
        return False
    local = email[:at]
    if len(local) == 0 or len(local) > _MAX_LOCAL_LENGTH:
        return False
    domain = email[at+1:]
    if domain.startswith("-") or domain.endswith("-"):
        return False
    if ".." in domain:
        return False
    labels = domain.split(".")
    if any(len(label) == 0 or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    return True

def unsubscribe(email: str) -> str:
    try:
        normalized = _normalize(email)
        if normalized is None or not _is_valid_email(normalized):
            return "Invalid email address."
        if normalized in _DB:
            _DB.remove(normalized)
            return "You have been unsubscribed."
        else:
            return "Email not found in database."
    except Exception:
        return "An error occurred processing your request."

def _seed_db():
    _DB.clear()
    _DB.update({
        "a@example.com",
        "b@example.org",
        "c+news@domain.co",
        "user@sub.domain.com",
        "test@example.com",
    })

if __name__ == "__main__":
    _seed_db()
    tests = [
        "a@example.com",
        "  TEST@example.com  ",
        "notfound@nowhere.net",
        "invalid-email",
        "C+News@Domain.Co",
    ]
    for t in tests:
        print(f"Input: {t} -> {unsubscribe(t)}")