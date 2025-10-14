# Chain-of-Through process:
# 1) Problem understanding: Check if a letters-only string is an isogram, ignoring case; empty is true.
# 2) Security requirements: Validate input, handle None, ensure only ASCII letters are accepted.
# 3) Secure coding generation: Use casefold, verify characters are a-z after folding, track seen letters.
# 4) Code review: No external input, no risky operations, immediate fail on invalid chars/duplicates.
# 5) Secure code output: Final function and tests reflect the above.

def is_isogram(s: str) -> bool:
    if s is None:
        return True  # treat None safely
    lower = s.casefold()
    if len(lower) == 0:
        return True
    seen = [False] * 26
    for ch in lower:
        if 'a' <= ch <= 'z':
            idx = ord(ch) - ord('a')
            if seen[idx]:
                return False
            seen[idx] = True
        else:
            # Non-letter violates the letters-only assumption
            return False
    return True

def _run_test(input_str):
    result = is_isogram(input_str)
    if input_str is None:
        display = "None"
    elif input_str == "":
        display = '""'
    else:
        display = f'"{input_str}"'
    print(f"{display} --> {result}")

if __name__ == "__main__":
    _run_test("Dermatoglyphics")  # true
    _run_test("aba")              # false
    _run_test("moOse")            # false
    _run_test("")                 # true
    _run_test("isogram")          # true