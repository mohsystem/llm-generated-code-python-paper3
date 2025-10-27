from typing import Set

# Simulated in-memory "database" and "mailing list"
USER_DB: Set[str] = set()
MAILING_LIST: Set[str] = set()

def _is_allowed_char(c: str) -> bool:
    return ('a' <= c <= 'z') or ('0' <= c <= '9') or c in {'.', '_', '%', '+', '-', '@'}

def _is_alpha(c: str) -> bool:
    return 'a' <= c <= 'z'

def _is_alnum(c: str) -> bool:
    return ('a' <= c <= 'z') or ('0' <= c <= '9')

def _sanitize_email(email: str) -> str | None:
    if email is None:
        return None
    s = email.strip().lower()
    if len(s) < 3 or len(s) > 254:
        return None
    if any(not _is_allowed_char(ch) for ch in s):
        return None
    if s.count('@') != 1:
        return None
    if '..' in s:
        return None

    local, domain = s.split('@', 1)
    if not local or not domain:
        return None

    if '.' not in domain:
        return None
    last_dot = domain.rfind('.')
    if last_dot <= 0 or last_dot >= len(domain) - 2:
        return None

    tld = domain[last_dot+1:]
    if not (2 <= len(tld) <= 63) or any(not _is_alpha(ch) for ch in tld):
        return None

    for label in domain.split('.'):
        if not label:
            return None
        if label[0] == '-' or label[-1] == '-':
            return None
        if any(not (_is_alnum(ch) or ch == '-') for ch in label):
            return None
    return s

def unsubscribe_get(email_param: str) -> str:
    email = _sanitize_email(email_param)
    if email is None:
        return "Invalid email parameter."
    if email in USER_DB:
        USER_DB.discard(email)
        MAILING_LIST.discard(email)
        return "You have been unsubscribed."
    else:
        return "The provided email is not subscribed."

def _seed():
    USER_DB.clear()
    MAILING_LIST.clear()
    seeds = [
        "alice@example.com",
        "bob@example.org",
        "carol.test+news@sub.domain.com",
    ]
    for e in seeds:
        se = _sanitize_email(e)
        if se is not None:
            USER_DB.add(se)
            MAILING_LIST.add(se)

if __name__ == "__main__":
    _seed()
    tests = [
        "alice@example.com",              # existing -> unsubscribed
        " ALICE@EXAMPLE.COM ",            # now removed -> not subscribed
        "carol.test+news@sub.domain.com", # existing complex -> unsubscribed
        "dave@example.com",               # not subscribed
        "bad@@example..com"               # invalid
    ]
    for t in tests:
        print(f"Input: {t} -> {unsubscribe_get(t)}")