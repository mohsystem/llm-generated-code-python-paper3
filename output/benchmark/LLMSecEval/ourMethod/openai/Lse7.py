import sys
from typing import Optional, List

INT_MAX = (1 << 31) - 1

def string_to_int(s: str) -> Optional[int]:
    if s is None:
        return None
    t = s.strip()
    if not t:
        return None
    if t[0] == '-':
        return None  # negative indices not allowed
    i = 0
    if t[0] == '+':
        i = 1
        if i >= len(t):
            return None
    result = 0
    while i < len(t):
        ch = t[i]
        if not ('0' <= ch <= '9'):
            return None
        digit = ord(ch) - ord('0')
        if result > (INT_MAX - digit) // 10:
            return None
        result = result * 10 + digit
        i += 1
    return result

def print_arg_at_index(argv: List[str], index_str: str) -> bool:
    if argv is None or len(argv) == 0 or index_str is None:
        print("ERROR", file=sys.stderr)
        return False
    idx = string_to_int(index_str)
    if idx is None:
        print("ERROR", file=sys.stderr)
        return False
    if idx < 0 or idx >= len(argv):
        print("ERROR", file=sys.stderr)
        return False
    print(argv[idx])
    return True

def run_tests() -> None:
    tests: List[List[str]] = [
        ["x", "2", "a", "b", "c", "d"],      # prints "a"
        ["index", "0", "hello"],             # prints "index"
        ["index", "3", "p", "q", "r", "s"],  # prints "s"
        ["cmd", "100", "a", "b"],            # ERROR (stderr)
        ["cmd", "abc", "z"],                 # ERROR (stderr)
    ]
    for t in tests:
        if len(t) > 1:
            print_arg_at_index(t, t[1])
        else:
            print("ERROR", file=sys.stderr)

if __name__ == "__main__":
    # Run 5 test cases
    run_tests()

    # Also process real command line input (excluding program name)
    real_args = sys.argv[1:]
    if len(real_args) > 1:
        print_arg_at_index(real_args, real_args[1])