import re
from typing import Pattern

# Precompile patterns
EMAIL_PATTERN: Pattern[str] = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
USERNAME_PATTERN: Pattern[str] = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,19}$")
PHONE_ALLOWED_PATTERN: Pattern[str] = re.compile(r"^[+0-9() .-]{7,20}$")
DATE_ISO_PATTERN: Pattern[str] = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")
PASSWORD_ALLOWED_PATTERN: Pattern[str] = re.compile(r"^[\S]{8,64}$")
PW_LOWER: Pattern[str] = re.compile(r"[a-z]")
PW_UPPER: Pattern[str] = re.compile(r"[A-Z]")
PW_DIGIT: Pattern[str] = re.compile(r"\d")
PW_SPECIAL: Pattern[str] = re.compile(r"[^A-Za-z0-9]")

def _within_length(s: str | None, min_len: int, max_len: int) -> bool:
    if s is None:
        return False
    length = len(s)
    return min_len <= length <= max_len

def is_valid_email(s: str) -> bool:
    if not _within_length(s, 3, 254):
        return False
    return EMAIL_PATTERN.fullmatch(s) is not None

def is_valid_username(s: str) -> bool:
    if not _within_length(s, 3, 20):
        return False
    return USERNAME_PATTERN.fullmatch(s) is not None

def is_valid_phone(s: str) -> bool:
    if not _within_length(s, 7, 20):
        return False
    if PHONE_ALLOWED_PATTERN.fullmatch(s) is None:
        return False
    digits = sum(ch.isdigit() for ch in s)
    return 7 <= digits <= 15

def is_valid_iso_date(s: str) -> bool:
    if not _within_length(s, 10, 10):
        return False
    return DATE_ISO_PATTERN.fullmatch(s) is not None

def is_valid_password(s: str) -> bool:
    if not _within_length(s, 8, 64):
        return False
    if PASSWORD_ALLOWED_PATTERN.fullmatch(s) is None:
        return False
    if PW_LOWER.search(s) is None:
        return False
    if PW_UPPER.search(s) is None:
        return False
    if PW_DIGIT.search(s) is None:
        return False
    if PW_SPECIAL.search(s) is None:
        return False
    return True

def main() -> None:
    emails = [
        "alice@example.com",
        "alice@@example.com",
        "user.name+tag@sub.domain.co",
        "no-at-symbol.domain",
        "this-is-long_but.valid-123@domain-info.org",
    ]
    usernames = [
        "Alice_01",
        "1bad",
        "ab",
        "Valid_User_20",
        "UserNameWithMaxLen20",
    ]
    phones = [
        "+1-202-555-0123",
        "12345",
        "(020) 7946 0958",
        "+44 20 7946 0958 12345",
        "202.555.0180",
    ]
    dates = [
        "2025-10-14",
        "2025-13-01",
        "2025-02-00",
        "1999-12-31",
        "abcd-ef-gh",
    ]
    passwords = [
        "Str0ng!Pwd",
        "weak",
        "NoSpecial123",
        "alllower!!1",
        "GoodPass#2025",
    ]

    for i in range(5):
        print(f"Test case #{i+1}")
        print(f"  Email: {emails[i]} -> {is_valid_email(emails[i])}")
        print(f"  Username: {usernames[i]} -> {is_valid_username(usernames[i])}")
        print(f"  Phone: {phones[i]} -> {is_valid_phone(phones[i])}")
        print(f"  Date: {dates[i]} -> {is_valid_iso_date(dates[i])}")
        # Do not print passwords or secrets
        print(f"  Password valid? -> {is_valid_password(passwords[i])}")

if __name__ == "__main__":
    main()