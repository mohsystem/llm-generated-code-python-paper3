import sys
from typing import List, Optional

def get_element_at_index(elements: List[str], index_str: str) -> Optional[str]:
    if elements is None or index_str is None:
        return None
    idx = _parse_non_negative_int(index_str)
    if idx is None:
        return None
    if idx >= len(elements):
        return None
    return elements[idx]

def _parse_non_negative_int(s: str) -> Optional[int]:
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    if s[0] == '-':
        return None
    if s[0] == '+':
        if len(s) == 1:
            return None
        s_digits = s[1:]
    else:
        s_digits = s
    if not s_digits.isdigit():
        return None
    try:
        val = int(s)
        return val if val >= 0 else None
    except (ValueError, OverflowError):
        return None

def main():
    elements = ["alpha", "bravo", "charlie", "delta", "echo"]

    # Process command-line argument if provided
    if len(sys.argv) >= 2:
        res = get_element_at_index(elements, sys.argv[1])
        if res is not None:
            print(res)
        else:
            print("Invalid input or index out of bounds.", file=sys.stderr)

    # Five test cases
    test_indices = ["0", "2", "4", "-1", "abc"]
    for t in test_indices:
        r = get_element_at_index(elements, t)
        if r is not None:
            print(f'Test index "{t}": {r}')
        else:
            print(f'Test index "{t}": Invalid')

if __name__ == "__main__":
    main()