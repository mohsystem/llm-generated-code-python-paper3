import sys

def trim_trailing(s):
    return None if s is None else s.rstrip()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(trim_trailing(sys.argv[1]))
    else:
        tests = [
            "hello   ",
            "test\t\t",
            "line\n",
            " mix  \t\n",
            "no-trim"
        ]
        for t in tests:
            print(trim_trailing(t))