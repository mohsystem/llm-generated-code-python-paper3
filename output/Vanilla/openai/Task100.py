import re
from typing import List

def search_in_file(pattern: str, filename: str) -> List[str]:
    matches: List[str] = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        for m in re.finditer(pattern, content):
            matches.append(m.group(0))
    except Exception:
        pass
    return matches

if __name__ == "__main__":
    import sys, os

    if len(sys.argv) >= 3:
        res = search_in_file(sys.argv[1], sys.argv[2])
        print(f"Matches: {len(res)}")
        for s in res:
            print(s)
        sys.exit(0)

    filename = "test_input.txt"
    content = (
        "foo bar baz 123 foo42\n"
        "New line with Foo and BAR.\n"
        "email: test@example.com; ip: 192.168.0.1; dates: 2025-10-04;\n"
        "ababa bab abab ababab\n"
    )
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

    patterns = [
        "foo",
        r"[0-9]+",
        r"(ab)+",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        r"192\.168\.[0-9]+\.[0-9]+",
    ]

    for i, p in enumerate(patterns, 1):
        res = search_in_file(p, filename)
        print(f"Test {i} Pattern: {p}")
        print(f"Matches: {len(res)}")
        for s in res:
            print(s)
        print("----")