import re
from typing import Set

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

def is_valid_email(email: str) -> bool:
    if not isinstance(email, str) or len(email) == 0 or len(email) > 254:
        return False
    return EMAIL_RE.fullmatch(email) is not None

def run_unsubscribe_script(email: str) -> int:
    # Secure stub: simulate a script call. For real execution, use subprocess with a fixed executable path and argument list.
    lower = email.lower()
    if lower.startswith("error") or "fail" in lower:
        return 2  # non-zero indicates failure
    return 0

def process_unsubscribe(email: str, database: Set[str]) -> int:
    if not is_valid_email(email) or database is None:
        return 0
    if email not in database:
        return 0
    exit_code = run_unsubscribe_script(email)
    return 1 if exit_code == 0 else 0

if __name__ == "__main__":
    db = {
        "alice@example.com",
        "bob@sample.org",
        "charlie@test.net",
        "dora@domain.com",
        "error@test.net",
    }
    tests = [
        "alice@example.com",   # exists, script OK -> 1
        "unknown@x.com",       # not exists -> 0
        "error@test.net",      # exists, script fails -> 0
        "invalid",             # invalid -> 0
        "dora@domain.com",     # exists, script OK -> 1
    ]
    for t in tests:
        print(f"Email: {t} => {process_unsubscribe(t, db)}")