import sys

def trim_trailing(s: str) -> str:
    if s is None:
        return None
    i = len(s)
    while i > 0 and s[i - 1].isspace():
        i -= 1
    return s[:i]

def main(argv):
    if len(argv) > 1:
        print(trim_trailing(argv[1]))
    else:
        tests = [
            "Hello World   ",
            "TrailingTabs\t\t\t",
            "LineEnd\n\n",
            "  LeadingShouldStay   ",
            "    ",
        ]
        for t in tests:
            print(trim_trailing(t))

if __name__ == "__main__":
    main(sys.argv)