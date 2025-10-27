from typing import Optional

def trim_trailing_whitespace(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return s.rstrip()

if __name__ == "__main__":
    import sys

    # Command-line behavior
    if len(sys.argv) > 1:
        out = trim_trailing_whitespace(sys.argv[1])
        print("" if out is None else out)

    # 5 test cases
    tests = [
        "hello   ",
        " no-trim",
        "tabs\t\t",
        "mixed spaces\t ",
        ""
    ]
    for t in tests:
        res = trim_trailing_whitespace(t)
        print("" if res is None else res)