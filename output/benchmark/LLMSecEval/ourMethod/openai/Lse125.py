from typing import Optional, List
import sys

def trim_trailing_whitespace(s: Optional[str]) -> str:
    if s is None:
        return ""
    return s.rstrip()

def main() -> None:
    # If a command-line argument is provided, trim trailing whitespace and print it.
    if len(sys.argv) > 1:
        print(trim_trailing_whitespace(sys.argv[1]))

    # Five test cases
    tests: List[str] = [
        "hello",
        "hello   ",
        "line\n",
        "tabs\t\t",
        "mix \t\n\r",
    ]
    for i, t in enumerate(tests, 1):
        res = trim_trailing_whitespace(t)
        print(f"TEST {i}: [{res}]")

if __name__ == "__main__":
    main()