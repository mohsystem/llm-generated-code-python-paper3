import re

EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PHONE = re.compile(r"^\+?[0-9]{1,3}?[-. ]?(\([0-9]{3}\)|[0-9]{3})[-. ]?[0-9]{3}[-. ]?[0-9]{4}$")
USERNAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,15}$")

def is_valid_email(s: str) -> bool:
    return EMAIL.fullmatch(s or "") is not None

def is_valid_phone(s: str) -> bool:
    return PHONE.fullmatch(s or "") is not None

def is_valid_username(s: str) -> bool:
    return USERNAME.fullmatch(s or "") is not None

def main():
    emails = [
        "user@example.com",
        "foo.bar+tag@sub.domain.co",
        "bad@domain",
        "noatsymbol.com",
        "user@domain.c",
    ]
    phones = [
        "+1 (555) 123-4567",
        "555-123-4567",
        "5551234567",
        "123-45-6789",
        "++1 555 123 4567",
    ]
    usernames = [
        "Alice_123",
        "a",
        "1start",
        "Good_Name",
        "ThisUsernameIsWayTooLong123",
    ]

    print("Email validations:")
    for e in emails:
        print(f"{e} -> {is_valid_email(e)}")

    print("\nPhone validations:")
    for p in phones:
        print(f"{p} -> {is_valid_phone(p)}")

    print("\nUsername validations:")
    for u in usernames:
        print(f"{u} -> {is_valid_username(u)}")

if __name__ == "__main__":
    main()