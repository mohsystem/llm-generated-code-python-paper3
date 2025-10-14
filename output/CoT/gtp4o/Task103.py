def is_strong_password(password: str) -> bool:
    if password is None:
        return False
    if len(password) < 8:
        return False

    has_lower = False
    has_upper = False
    has_digit = False

    for ch in password:
        if not has_lower and ch.islower():
            has_lower = True
        elif not has_upper and ch.isupper():
            has_upper = True
        elif not has_digit and ch.isdigit():
            has_digit = True

        if has_lower and has_upper and has_digit:
            break

    return has_lower and has_upper and has_digit


if __name__ == "__main__":
    tests = [
        "Password1",
        "password",
        "PASSWORD1",
        "Pass1",
        "StrongPass123",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test case {i}: {is_strong_password(t)}")