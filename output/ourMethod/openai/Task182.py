from typing import List

def clean_number(s: str) -> str:
    if s is None:
        return ""
    digits = "".join(ch for ch in s if ch.isdigit())
    if len(digits) == 11 and digits[0] == '1':
        digits = digits[1:]
    elif len(digits) != 10:
        return ""

    if not ('2' <= digits[0] <= '9'):
        return ""
    if not ('2' <= digits[3] <= '9'):
        return ""
    return digits

def main() -> None:
    tests: List[str] = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "1 (123) 456-7890",
    ]
    for t in tests:
        print(clean_number(t))

if __name__ == "__main__":
    main()