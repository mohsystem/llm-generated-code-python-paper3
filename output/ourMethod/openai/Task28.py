from typing import List, Sequence

def _sanitize_name(s: str) -> str:
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    sanitized = "".join(ch for ch in s if ch.isprintable())
    sanitized = sanitized.strip()
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    return sanitized

def likes_text(names: Sequence[str]) -> str:
    if names is None:
        names = []
    n = len(names)
    n1 = _sanitize_name(names[0]) if n > 0 else ""
    n2 = _sanitize_name(names[1]) if n > 1 else ""
    n3 = _sanitize_name(names[2]) if n > 2 else ""

    if n == 0:
        return "no one likes this"
    if n == 1:
        return f"{n1} likes this"
    if n == 2:
        return f"{n1} and {n2} like this"
    if n == 3:
        return f"{n1}, {n2} and {n3} like this"
    return f"{n1}, {n2} and {n - 2} others like this"

def main() -> None:
    # 5 test cases
    tests: List[List[str]] = [
        [],
        ["Peter"],
        ["Jacob", "Alex"],
        ["Max", "John", "Mark"],
        ["Alex", "Jacob", "Mark", "Max"],
    ]
    for t in tests:
        print(f"{t} --> {likes_text(t)}")

if __name__ == "__main__":
    main()