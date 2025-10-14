from typing import Any


def is_strong_password(pwd: Any) -> bool:
    if not isinstance(pwd, str):
        return False
    if len(pwd) < 8:
        return False

    has_upper = False
    has_lower = False
    has_digit = False

    for ch in pwd:
        if ch.isupper():
            has_upper = True
        elif ch.islower():
            has_lower = True
        elif ch.isdigit():
            has_digit = True
        if has_upper and has_lower and has_digit:
            break

    return has_upper and has_lower and has_digit


def main() -> None:
    tests = [
        "Short7",
        "alllowercase1",
        "ALLUPPERCASE1",
        "NoDigitsHere",
        "Str0ngPass",
    ]
    expected = [False, False, False, False, True]

    for i, exp in enumerate(expected):
        result = is_strong_password(tests[i])
        print(f"Test {i+1}: expected={exp}, got={result}, verdict={'PASS' if result == exp else 'FAIL'}")


if __name__ == "__main__":
    main()