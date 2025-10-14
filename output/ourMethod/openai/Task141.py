from typing import List

MAX_LEN: int = 1_000_000

def reverse_string(s: str) -> str:
    if not isinstance(s, str):
        raise TypeError("Input must be a string")
    if len(s) > MAX_LEN:
        raise ValueError("Input too long")
    return s[::-1]

if __name__ == "__main__":
    tests: List[str] = [
        "",
        "a",
        "abc",
        "Hello, World!",
        "12345!@#$%"
    ]
    for t in tests:
        print(reverse_string(t))