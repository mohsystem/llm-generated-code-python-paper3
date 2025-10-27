import sys
from typing import Any

def _is_whitespace_but_not_newline(c: str) -> bool:
    return c in (' ', '\t', '\v', '\f')

def _is_newline(c: str) -> bool:
    return c in ('\n', '\r')

def sanitize_argument(arg: Any) -> str:
    if arg is None:
        raise ValueError("Argument cannot be None.")
    if not isinstance(arg, str):
        raise TypeError("Argument must be a string.")

    s = arg
    end = len(s) - 1

    while end >= 0 and _is_whitespace_but_not_newline(s[end]):
        end -= 1

    while end >= 0 and _is_newline(s[end]):
        end -= 1

    return s[:end + 1] if end >= 0 else ""

if __name__ == "__main__":
    if len(sys.argv) == 2:
        try:
            print(sanitize_argument(sys.argv[1]))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # 5 test cases
        tests = [
            "Hello World   ",
            "Tabs and spaces\t \t   ",
            "Ends with newlines\n\n\r",
            "Mix \t\v\f\n\r",
            "",
        ]
        for t in tests:
            try:
                res = sanitize_argument(t)
                print(f"[{res}]")
            except Exception as e:
                print(f"Error: {e}")