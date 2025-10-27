# Chain-of-Through process in code generation:
# 1) Problem understanding: Return argv[int(argv[1])] from a list of strings; handle errors.
# 2) Security requirements: Validate types, bounds, and integer conversion.
# 3) Secure coding generation: Defensive checks and safe conversions.
# 4) Code review: Ensure no unchecked access or unhandled exceptions.
# 5) Secure code output: Robust function with test cases.

from typing import List, Optional

def get_value_at_index(argv: List[str]) -> Optional[str]:
    if argv is None or len(argv) < 2:
        return None
    try:
        idx = int(argv[1].strip())
    except Exception:
        return None
    if idx < 0 or idx >= len(argv):
        return None
    return argv[idx]

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ["prog", "2", "alpha", "beta", "gamma"],  # expect "alpha"
        ["prog", "0", "alpha"],                   # expect "prog"
        ["prog", "5", "a", "b"],                  # invalid -> None
        ["prog", "-1", "x", "y"],                 # invalid -> None
        ["prog", "notint", "x", "y"],             # invalid -> None
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {get_value_at_index(t)}")