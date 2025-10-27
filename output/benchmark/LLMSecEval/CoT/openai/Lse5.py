# Chain-of-Through process:
# 1) Problem understanding:
#    - Create a list of elements.
#    - Read a command-line argument, convert to integer, print element at that index.
#    - Provide function taking parameters and returning the output.
# 2) Security requirements:
#    - Validate presence of argument, safe integer parsing, and bounds checks.
# 3) Secure coding generation:
#    - Use try/except for int conversion, ensure 0 <= index < len(elements).
# 4) Code review:
#    - No unchecked indexing; clear error messages; no unsafe operations.
# 5) Secure code output:
#    - Apply checks and print element or errors accordingly.

import sys
from typing import List, Optional

ELEMENTS: List[str] = ["alpha", "beta", "gamma", "delta", "epsilon"]

def element_at_index(elements: List[str], index: int) -> Optional[str]:
    if elements is None:
        return None
    if index < 0 or index >= len(elements):
        return None
    return elements[index]

def process_argument(arg: str) -> None:
    if arg is None:
        print("Error: No index argument provided.", file=sys.stderr)
        return
    try:
        idx = int(arg.strip())
    except (ValueError, TypeError):
        print("Error: Index must be a valid integer.", file=sys.stderr)
        return

    result = element_at_index(ELEMENTS, idx)
    if result is None:
        print(f"Error: Index out of bounds. Valid range is 0 to {len(ELEMENTS) - 1}.", file=sys.stderr)
    else:
        print(result)

def main() -> None:
    if len(sys.argv) >= 2:
        process_argument(sys.argv[1])
    else:
        # 5 test cases
        tests = [0, 2, 4, -1, 5]
        for t in tests:
            res = element_at_index(ELEMENTS, t)
            if res is None:
                print(f"Test index {t}: Error - Index out of bounds. Valid range is 0 to {len(ELEMENTS) - 1}.", file=sys.stderr)
            else:
                print(f"Test index {t}: {res}")

if __name__ == "__main__":
    main()