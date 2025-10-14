# Chain-of-Through process in code generation:
# 1) Problem understanding: Read a string, process by trimming, collapsing whitespace to single spaces, and converting to uppercase.
# 2) Security requirements: Python strings are safe; avoid unsafe buffer ops; handle None and empty input.
# 3) Secure coding generation: Use regex for whitespace normalization, robust input read.
# 4) Code review: No raw buffers, no risky conversions, straightforward logic.
# 5) Secure code output: Final code adheres to safe practices.

import re

def process_input(s: str) -> str:
    if s is None:
        return ""
    collapsed = re.sub(r"\s+", " ", s).strip()
    return collapsed.upper()

def main():
    try:
        user_input = input()
    except EOFError:
        user_input = ""
    print(process_input(user_input))

    # 5 test cases
    tests = [
        "  Hello,   world!  ",
        "",
        "Tabs\tand\nnewlines",
        "1234 abc DEF",
        "   multiple    spaces   here   ",
    ]
    for t in tests:
        print(process_input(t))

if __name__ == "__main__":
    main()