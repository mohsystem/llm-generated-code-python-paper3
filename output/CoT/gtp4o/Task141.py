# Chain-of-Through process via comments for secure coding.
# 1) Problem: reverse a string.
# 2) Security: handle None safely; no I/O risks.
# 3) Secure generation: immutable operations, no unsafe libs.
# 4) Review: minimal, clear, handles None.
# 5) Final secure output below.

def reverse_string(s):
    if s is None:
        return None
    return s[::-1]

if __name__ == "__main__":
    tests = ["", "hello", "A", "racecar", "Hello, World!"]
    for t in tests:
        r = reverse_string(t)
        print(f'Input: "{t}" -> Reversed: "{r}"')