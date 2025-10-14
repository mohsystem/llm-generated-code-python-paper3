# Chain-of-Through process in code generation:
# 1) Problem understanding: validate inputs (email, phone, username, password, URL) using regular expressions.
# 2) Security requirements: anchor patterns, bound input sizes, avoid complex/backtracking-heavy constructs.
# 3) Secure coding generation: length checks, compiled regex, supplemental checks.
# 4) Code review: ensured anchors, limited lengths, no eval/exec, safe prints.
# 5) Secure code output: final code with 5 test cases in main.

import re

MAX_EMAIL_LEN = 320
MAX_PHONE_LEN = 16
MIN_USERNAME_LEN = 2
MAX_USERNAME_LEN = 30
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 64
MAX_URL_LEN = 2083

EMAIL_RE = re.compile(
    r'^[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
)
PHONE_RE = re.compile(r'^\+?[1-9]\d{1,14}$')
USERNAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,28}[A-Za-z0-9])?$')
PWD_HAS_LOWER = re.compile(r'[a-z]')
PWD_HAS_UPPER = re.compile(r'[A-Z]')
PWD_HAS_DIGIT = re.compile(r'\d')
PWD_HAS_SPECIAL = re.compile(r'[^A-Za-z0-9\s]')
PWD_HAS_SPACE = re.compile(r'\s')
URL_RE = re.compile(
    r'^https?://(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?::\d{2,5})?(?:/[A-Za-z0-9._~!$&\'()*+,;=:@%/\-?]*)?$'
)

def _within(s: str, min_len: int, max_len: int) -> bool:
    return isinstance(s, str) and min_len <= len(s) <= max_len

def validate_email(input_str: str) -> bool:
    if not _within(input_str, 3, MAX_EMAIL_LEN):
        return False
    if not EMAIL_RE.fullmatch(input_str):
        return False
    local, _, domain = input_str.partition('@')
    if '..' in local or '..' in domain:
        return False
    return True

def validate_phone_e164(input_str: str) -> bool:
    if not _within(input_str, 2, MAX_PHONE_LEN):
        return False
    return PHONE_RE.fullmatch(input_str) is not None

def validate_username(input_str: str) -> bool:
    if not _within(input_str, MIN_USERNAME_LEN, MAX_USERNAME_LEN):
        return False
    if not USERNAME_RE.fullmatch(input_str):
        return False
    specials = {'.', '_', '-'}
    for a, b in zip(input_str, input_str[1:]):
        if a in specials and b in specials:
            return False
    return True

def validate_strong_password(input_str: str) -> bool:
    if not _within(input_str, MIN_PASSWORD_LEN, MAX_PASSWORD_LEN):
        return False
    if PWD_HAS_SPACE.search(input_str):
        return False
    if not PWD_HAS_LOWER.search(input_str):
        return False
    if not PWD_HAS_UPPER.search(input_str):
        return False
    if not PWD_HAS_DIGIT.search(input_str):
        return False
    if not PWD_HAS_SPECIAL.search(input_str):
        return False
    return True

def validate_url(input_str: str) -> bool:
    if not _within(input_str, 8, MAX_URL_LEN):
        return False
    return URL_RE.fullmatch(input_str) is not None

def main():
    emails = [
        "user@example.com",
        "first.last+alias@sub.domain.co",
        ".user@domain.com",
        "user..name@domain.com",
        "user@-domain.com",
    ]
    phones = ["+14155552671", "4155552671", "+001234", "++123", "+1234567890123456"]
    usernames = ["alice_01", "a", "user--name", "_user", "valid.user-name"]
    passwords = ["Abcdef1!", "short1!", "NoDigits!", "noupper1!", "With Space1!"]
    urls = [
        "https://example.com",
        "http://sub.domain.co:8080/path/to/resource?x=1",
        "ftp://example.com",
        "http://-bad.com",
        "http://example",
    ]

    for e in emails:
        print(f"Email: {e} -> {validate_email(e)}")
    for p in phones:
        print(f"Phone: {p} -> {validate_phone_e164(p)}")
    for u in usernames:
        print(f"Username: {u} -> {validate_username(u)}")
    for pw in passwords:
        print(f"Password: {pw} -> {validate_strong_password(pw)}")
    for url in urls:
        print(f"URL: {url} -> {validate_url(url)}")

if __name__ == "__main__":
    main()