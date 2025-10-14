# Chain-of-Through Process:
# 1) Problem understanding: Combine s1 and s2 letters, keep distinct letters, return sorted string.
# 2) Security requirements: Normalize case, filter only a-z, avoid unsafe eval or external I/O.
# 3) Secure coding generation: Use set for dedup; handle None inputs defensively.
# 4) Code review: Ensure only [a-z] retained; sorting deterministic.
# 5) Secure code output: Return a new string with letters a..z present in inputs.

def longest(s1: str, s2: str) -> str:
    s1 = s1 or ""
    s2 = s2 or ""
    combined = (s1 + s2).lower()
    letters = {c for c in combined if 'a' <= c <= 'z'}
    return ''.join(sorted(letters))

if __name__ == "__main__":
    tests = [
        ("xyaabbbccccdefww", "xxxxyyyyabklmopq"),
        ("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("abc", "def"),
        ("zzz", "zzzz"),
        ("", "abc"),
    ]
    for i, (a, b) in enumerate(tests, 1):
        print(f"Test {i}: {longest(a, b)}")