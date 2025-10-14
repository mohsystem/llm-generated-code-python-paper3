import sys
import re

def process(s: str) -> str:
    if s is None:
        return ""
    s = s.strip()
    s = re.sub(r"\s+", " ", s)
    return s.upper()

if __name__ == "__main__":
    user_input = sys.stdin.readline()
    if user_input:
        print(process(user_input))
    tests = [
        "  hello   world  ",
        "\tMixed\tCase Input\n",
        "already CLEAN",
        "   ",
        "Symbols 123 !@#   test",
    ]
    for t in tests:
        print(process(t))