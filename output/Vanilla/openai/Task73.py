def is_valid_admin_password(pwd: str) -> bool:
    if pwd is None or len(pwd) < 12:
        return False

    has_upper = has_lower = has_digit = has_special = False

    prev1 = prev2 = None
    for ch in pwd:
        if ch.isspace():
            return False
        if ch.isupper():
            has_upper = True
        elif ch.islower():
            has_lower = True
        elif ch.isdigit():
            has_digit = True
        else:
            has_special = True

        if prev1 is not None and prev2 is not None:
            if ch == prev1 == prev2:
                return False
        prev2, prev1 = prev1, ch

    if not (has_upper and has_lower and has_digit and has_special):
        return False

    lower_pwd = pwd.lower()
    bad_equals = {"password", "admin", "admin123", "123456", "qwerty", "letmein", "welcome", "passw0rd", "iloveyou"}
    if lower_pwd in bad_equals:
        return False
    bad_contains = ["admin", "password", "qwerty", "12345"]
    if any(b in lower_pwd for b in bad_contains):
        return False

    return True


if __name__ == "__main__":
    tests = [
        "Admin@123",
        "Str0ng!AdminPwd",
        "CorrectHorse9!",
        "aaaaaaaaaaaa",
        "N0_Spaces-Allowed?"
    ]
    for t in tests:
        print(f"{t} -> {is_valid_admin_password(t)}")