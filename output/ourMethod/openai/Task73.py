from typing import List, Set

def is_valid_admin_password(password: str) -> bool:
    if not isinstance(password, str):
        return False

    min_len = 12
    max_len = 128
    n = len(password)
    if n < min_len or n > max_len:
        return False

    # Printable ASCII only (33..126)
    for ch in password:
        code = ord(ch)
        if code < 33 or code > 126:
            return False

    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False

    repeat_run = 1
    for i, ch in enumerate(password):
        if ch.isupper():
            has_upper = True
        elif ch.islower():
            has_lower = True
        elif ch.isdigit():
            has_digit = True
        else:
            has_special = True

        if i > 0:
            if password[i] == password[i - 1]:
                repeat_run += 1
                if repeat_run >= 3:
                    return False
            else:
                repeat_run = 1

    if not (has_upper and has_lower and has_digit and has_special):
        return False

    lower = password.lower()
    if "admin" in lower:
        return False
    if "password" in lower or "qwerty" in lower:
        return False

    banned: Set[str] = {
        "admin", "admin123", "admin@123", "administrator",
        "password", "passw0rd", "p@ssw0rd", "p4ssw0rd",
        "qwerty", "qwerty123", "letmein", "welcome",
        "123456", "123456789", "iloveyou", "12345678"
    }
    if lower in banned:
        return False

    if _has_sequential_run(password):
        return False

    return True

def _has_sequential_run(s: str) -> bool:
    for i in range(2, len(s)):
        a, b, c = s[i - 2], s[i - 1], s[i]
        if a.isalpha() and b.isalpha() and c.isalpha():
            x, y, z = ord(a.lower()), ord(b.lower()), ord(c.lower())
            if (y == x + 1 and z == y + 1) or (y == x - 1 and z == y - 1):
                return True
        elif a.isdigit() and b.isdigit() and c.isdigit():
            x, y, z = ord(a), ord(b), ord(c)
            if (y == x + 1 and z == y + 1) or (y == x - 1 and z == y - 1):
                return True
    return False

if __name__ == "__main__":
    tests: List[str] = [
        "Admin@123",       # invalid
        "S3cure#Admin!",   # invalid
        "G00d#Pa55word!",  # valid
        "aaaaaaaaaaaa",    # invalid
        "N0t$0Obv10us!"    # valid
    ]
    for i, _pwd in enumerate(tests, start=1):
        res = is_valid_admin_password(_pwd)
        print(f"Test {i}: {res}")