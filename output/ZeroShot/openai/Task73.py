from typing import Set

MIN_LENGTH = 12
MAX_LENGTH = 128
COMMON_PASSWORDS: Set[str] = {
    "password","123456","qwerty","letmein","welcome","admin","administrator","passw0rd",
    "iloveyou","monkey","dragon","football","abc123","123456789","12345678","111111",
    "123123","login","princess","admin123","adminadmin","root","root123"
}

def is_valid_admin_password(password: str) -> bool:
    if password is None:
        return False
    n = len(password)
    if n < MIN_LENGTH or n > MAX_LENGTH:
        return False

    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        return False
    if "admin" in lower or "administrator" in lower or "root" in lower:
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any((not c.isalnum()) and (not c.isspace()) for c in password)
    if not (has_upper and has_lower and has_digit and has_special):
        return False

    # no whitespace
    if any(c.isspace() for c in password):
        return False

    # triple repeat
    rep = 1
    for i in range(1, n):
        if password[i] == password[i-1]:
            rep += 1
            if rep >= 3:
                return False
        else:
            rep = 1

    # sequential patterns of length >= 4 (letters or digits)
    l = lower
    for i in range(n - 3):
        seg = l[i:i+4]
        if all('a' <= ch <= 'z' for ch in seg):
            asc = all(ord(seg[k+1]) == ord(seg[k]) + 1 for k in range(3))
            desc = all(ord(seg[k+1]) == ord(seg[k]) - 1 for k in range(3))
            if asc or desc:
                return False
        if all(ch.isdigit() for ch in seg):
            asc = all(ord(seg[k+1]) == ord(seg[k]) + 1 for k in range(3))
            desc = all(ord(seg[k+1]) == ord(seg[k]) - 1 for k in range(3))
            if asc or desc:
                return False

    return True

if __name__ == "__main__":
    tests = [
        "password",          # False
        "Admin123!",         # False
        "StrongPassw0rd!",   # True
        "Adm!nStrong#2024",  # True
        "Abcd1234!xyZ"       # False
    ]
    for t in tests:
        print("true" if is_valid_admin_password(t) else "false")