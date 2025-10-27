import sys
from typing import List, Optional

def arg_at_index(index: int, argv_including_program_name: List[str]) -> Optional[str]:
    if argv_including_program_name is None:
        return None
    if index < 0 or index >= len(argv_including_program_name):
        return None
    return argv_including_program_name[index]

def _parse_non_negative_int(s: str) -> Optional[int]:
    if s is None:
        return None
    t = s.strip()
    if not t:
        return None
    if t[0] == '+':
        t2 = t[1:]
    elif t[0] == '-':
        return None
    else:
        t2 = t
    if not t2.isdigit():
        return None
    try:
        val = int(t)
    except Exception:
        return None
    if val < 0:
        return None
    return val

def main() -> None:
    if len(sys.argv) > 1:
        idx = _parse_non_negative_int(sys.argv[1])
        if idx is None:
            print("Error: index must be a non-negative integer.", file=sys.stderr)
            sys.exit(1)
        if idx < 0 or idx >= len(sys.argv):
            print("Error: index out of range.", file=sys.stderr)
            sys.exit(1)
        # sys.argv includes program name at index 0
        print(sys.argv[idx])
        return

    # Test cases (run when no CLI args are provided)
    tests = [
        (0, ["prog", "1", "alpha", "beta", "gamma"]),
        (1, ["prog", "1", "alpha", "beta", "gamma"]),
        (2, ["prog", "1", "alpha", "beta", "gamma"]),
        (3, ["prog", "3", "foo", "bar", "baz"]),
        (0, ["prog", "0"]),
    ]
    for idx, argv in tests:
        res = arg_at_index(idx, argv)
        print("" if res is None else res)

if __name__ == "__main__":
    main()