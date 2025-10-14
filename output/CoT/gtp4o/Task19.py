# Chain-of-Through process in code generation:
# 1) Problem understanding: Reverse words with length >= 5.
# 2) Security: No eval/use of unsafe constructs; pure function.
# 3) Implementation: Use split with explicit separator to preserve spaces.
# 4) Review: No global state, handles None safely.
# 5) Output: Final tested function with main tests.

def spin_words(s: str) -> str:
    if s is None:
        return None
    return ' '.join(w[::-1] if len(w) >= 5 else w for w in s.split(' '))

if __name__ == "__main__":
    tests = [
        "Hey fellow warriors",
        "This is a test",
        "This is another test",
        "Welcome",
        "abcd efghi jklmn op qrstu vwxyz",
    ]
    for t in tests:
        print(spin_words(t))