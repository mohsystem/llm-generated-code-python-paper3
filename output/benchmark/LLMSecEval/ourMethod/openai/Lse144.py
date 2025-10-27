from typing import Callable, Iterable, Set

MAX_EMAIL_LEN = 254

def is_valid_email(email: str) -> bool:
    if email is None:
        return False
    trimmed = email.strip()
    ln = len(trimmed)
    if ln < 3 or ln > MAX_EMAIL_LEN:
        return False
    if trimmed.count("@") != 1:
        return False
    local, domain = trimmed.split("@", 1)
    if not local or len(local) > 64:
        return False
    # local: A-Za-z0-9._+-, no starting/ending dot, no consecutive dots
    if local[0] == "." or local[-1] == ".":
        return False
    prev_dot = False
    for ch in local:
        if ch.isalnum() or ch in "._+-":
            if ch == ".":
                if prev_dot:
                    return False
                prev_dot = True
            else:
                prev_dot = False
        else:
            return False
    # domain must contain at least one dot
    if "." not in domain:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False
    if len(labels[-1]) < 2:
        return False
    return True

def normalize_email(email: str) -> str:
    return email.strip().lower()

def process_unsubscribe(email: str, database: Iterable[str], script: Callable[[str], int]) -> int:
    if email is None or database is None or script is None:
        return 0
    if not is_valid_email(email):
        return 0
    # normalize database into a set of lowercase emails
    norm_db: Set[str] = set()
    for e in database:
        if isinstance(e, str) and is_valid_email(e):
            norm_db.add(normalize_email(e))
    norm_email = normalize_email(email)
    if norm_email not in norm_db:
        return 0
    try:
        rc = script(norm_email)
    except Exception:
        return 0
    return 1 if rc == 0 else 0

# Example script: success (0) for @example.com, else non-zero
def example_script(email: str) -> int:
    return 0 if email.endswith("@example.com") else 3

if __name__ == "__main__":
    db = [
        "alice@example.com",
        "bob@example.com",
        "carol@block.example",
        "dave@example.org",
        "eve@example.net",
    ]
    tests = [
        "alice@example.com",      # exists, script=0 -> 1
        "carol@block.example",    # exists, script!=0 -> 0
        "frank@example.com",      # not exists -> 0
        "bad@@example.com",       # invalid -> 0
        "dave@example.org",       # exists, script!=0 -> 0
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {process_unsubscribe(t, db, example_script)}")