# Chain-of-Through process:
# 1) Problem understanding: Convert a string to int safely, then print argv[INDEX] where INDEX is argv[1].
# 2) Security requirements: Validate digits, non-negative, avoid overflows and OOB access.
# 3) Secure coding generation: Manual parsing with bounds checks and guarded indexing.
# 4) Code review: Ensure all branches handle invalid inputs gracefully.
# 5) Secure code output: Final code prints only valid selections or "ERROR".

from typing import List, Optional

INT_MAX = 2**31 - 1

def safe_str_to_int(s: str) -> Optional[int]:
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    i = 0
    if s[0] == '+':
        i = 1
        if len(s) == 1:
            return None
    elif s[0] == '-':
        return None
    val = 0
    for ch in s[i:]:
        if ch < '0' or ch > '9':
            return None
        val = val * 10 + (ord(ch) - 48)
        if val > INT_MAX:
            return None
    return val

def get_arg_at_index(argv: List[str], index_str: str) -> Optional[str]:
    idx = safe_str_to_int(index_str)
    if idx is None:
        return None
    if idx < 0 or idx >= len(argv):
        return None
    return argv[idx]

def print_at_index(argv: List[str], index_str: str) -> Optional[str]:
    val = get_arg_at_index(argv, index_str)
    if val is None:
        print("ERROR")
        return None
    print(val)
    return val

if __name__ == "__main__":
    tests = [
        ["a", "2", "alpha", "beta", "gamma"],  # prints alpha
        ["first", "0", "hello"],               # prints first
        ["cat", "3", "a", "b", "c", "d"],      # prints d
        ["oops", "notnum", "foo"],             # ERROR
        ["few", "9", "only", "two"],           # ERROR
    ]
    for t in tests:
        idx_str = t[1] if len(t) > 1 else ""
        print_at_index(t, idx_str)