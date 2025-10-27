import sys
from typing import List, Optional, Tuple

def try_parse_non_negative_int(s: str) -> Tuple[bool, int]:
    if s is None:
        return False, 0
    t = s.strip()
    if not t:
        return False, 0
    if t[0] == '+':
        t = t[1:]
        if not t:
            return False, 0
    if t[0] == '-':
        return False, 0
    if not all('0' <= ch <= '9' for ch in t):
        return False, 0
    val = 0
    for ch in t:
        val = val * 10 + (ord(ch) - 48)
        if val > 2**31 - 1:
            return False, 0
    return True, val

def get_arg_at_index(args: List[str], index_str: str) -> Optional[str]:
    ok, idx = try_parse_non_negative_int(index_str)
    if not ok:
        return None
    if idx < 0 or idx >= len(args):
        return None
    return args[idx]

def print_arg_at_index(args: List[str], index_str: str) -> None:
    v = get_arg_at_index(args, index_str)
    if v is not None:
        print(v)

def main():
    # If run with CLI arguments, use the second argument as index, and print the argument at that index.
    if len(sys.argv) > 1:
        print_arg_at_index(sys.argv, sys.argv[1])

    # 5 test cases
    tests = [
        ["a0", "2", "x0", "x1", "x2"],        # prints x0
        ["first", "0", "z"],                  # prints first
        ["foo", "3", "aa", "bb", "cc", "dd"], # prints dd
        ["unused", "-1", "val"],              # prints nothing (invalid)
        ["hello", "abc", "p", "q"],           # prints nothing (invalid)
    ]
    for t in tests:
        print_arg_at_index(t, t[1])

if __name__ == "__main__":
    main()