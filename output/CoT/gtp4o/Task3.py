# Chain-of-Through Step 1: Problem understanding - pangram detection ignoring non-letters, case-insensitive.
# Chain-of-Through Step 2: Security requirements - no unsafe eval/input; handle None safely.
# Chain-of-Through Step 3: Secure coding generation - process only 'a'-'z', early exit when all seen.
# Chain-of-Through Step 4: Code review - no external dependencies or unsafe operations.
# Chain-of-Through Step 5: Secure code output - finalized implementation.

def is_pangram(s: str) -> bool:
    if s is None:
        return False
    seen = [False] * 26
    count = 0
    for ch in s:
        c = ch.lower()
        if 'a' <= c <= 'z':
            idx = ord(c) - ord('a')
            if not seen[idx]:
                seen[idx] = True
                count += 1
                if count == 26:
                    return True
    return count == 26

if __name__ == "__main__":
    tests = [
        "The quick brown fox jumps over the lazy dog",
        "Hello, world!",
        "",
        "Sphinx of black quartz, judge my vow 123!!!",
        "abcdefghijklmno pqrstuvwxy"
    ]
    for t in tests:
        print("True" if is_pangram(t) else "False")