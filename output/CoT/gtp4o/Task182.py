# Task182 - Python implementation
# Chain-of-Through process:
# 1) Problem understanding: Normalize NANP numbers by stripping punctuation and optional country code 1.
# 2) Security: Handle None safely, avoid using eval or risky ops.
# 3) Secure coding: Iterate characters, keep digits, validate rules.
# 4) Review: Ensure proper length and NXX constraints.
# 5) Output: Return 10-digit string or empty string on invalid.

def clean(input_str: str) -> str:
    if input_str is None:
        return ""
    s = str(input_str)
    digits = []
    for ch in s:
        if ch.isdigit():
            digits.append(ch)
    if len(digits) == 11:
        if digits[0] != '1':
            return ""
        digits = digits[1:]
    if len(digits) != 10:
        return ""
    if not ('2' <= digits[0] <= '9'):
        return ""
    if not ('2' <= digits[3] <= '9'):
        return ""
    return "".join(digits)

if __name__ == "__main__":
    tests = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "1 123 456 7890"
    ]
    for t in tests:
        print(clean(t))