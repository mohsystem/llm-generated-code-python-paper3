import re

def clean_number(s: str) -> str:
    if s is None:
        return ""
    digits = re.sub(r"\D", "", s)
    if len(digits) == 11 and digits[0] == '1':
        digits = digits[1:]
    if len(digits) != 10:
        return ""
    if not ('2' <= digits[0] <= '9'):
        return ""
    if not ('2' <= digits[3] <= '9'):
        return ""
    return digits

if __name__ == "__main__":
    tests = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "212-055-1234"
    ]
    for t in tests:
        print(clean_number(t))