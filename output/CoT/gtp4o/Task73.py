# Step 1-5 combined into secure implementation

def is_valid_admin_password(pwd: str) -> bool:
    if not isinstance(pwd, str):
        return False

    length = len(pwd)
    if length < 12 or length > 128:
        return False

    has_upper = has_lower = has_digit = has_special = False

    repeat_count = 1
    for i, ch in enumerate(pwd):
        if ch.isspace():
            return False

        if ch.isupper():
            has_upper = True
        elif ch.islower():
            has_lower = True
        elif ch.isdigit():
            has_digit = True

        if not ch.isalnum() and not ch.isspace():
            has_special = True

        if i > 0:
            if ch == pwd[i - 1]:
                repeat_count += 1
                if repeat_count >= 3:
                    return False
            else:
                repeat_count = 1

    if not (has_upper and has_lower and has_digit and has_special):
        return False

    lower = pwd.lower()
    banned = ["password", "admin", "qwerty", "letmein", "123456"]
    if any(b in lower for b in banned):
        return False

    if _has_consecutive_sequence_digits(pwd) or _has_consecutive_sequence_letters(pwd):
        return False

    return True


def _has_consecutive_sequence_digits(s: str) -> bool:
    run = 1
    prev = None
    for ch in s:
        if not ch.isdigit():
            run = 1
            prev = None
            continue
        if prev is not None:
            if ord(ch) == ord(prev) + 1 or ord(ch) == ord(prev) - 1:
                run += 1
                if run >= 4:
                    return True
            else:
                run = 1
        prev = ch
    return False


def _has_consecutive_sequence_letters(s: str) -> bool:
    run = 1
    prev = None
    for ch in s:
        if not ch.isalpha():
            run = 1
            prev = None
            continue
        c = ch.lower()
        if prev is not None:
            if ord(c) == ord(prev) + 1 or ord(c) == ord(prev) - 1:
                run += 1
                if run >= 4:
                    return True
            else:
                run = 1
        prev = c
    return False


if __name__ == "__main__":
    tests = [
        "password123!",
        "Admin123!",
        "ValidStrong#2024Xx",
        "NoSpecialChar1234",
        "AAAaaa111!!!",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {is_valid_admin_password(t)}")