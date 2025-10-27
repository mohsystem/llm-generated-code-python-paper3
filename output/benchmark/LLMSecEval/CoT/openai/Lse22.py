# Chain-of-Through process in code generation:
# 1) Problem understanding: Generate a random number larger than 1000 and print it.
# 2) Security requirements: Use a strong random source and validate bounds.
# 3) Secure coding generation: Implement with secrets, safe bounds, and overflow checks.
# 4) Code review: Ensure no overflow, handle edge cases, no insecure randomness.
# 5) Secure code output: Finalized after review.

import secrets

def generate_random_above(min_exclusive: int) -> int:
    lower = max(1000, int(min_exclusive)) + 1
    upper = min((2**31 - 1), lower + 1_000_000)
    if upper < lower:
        upper = lower
    bound = max(1, upper - lower + 1)
    offset = secrets.randbelow(bound)
    return lower + offset

def main():
    tests = [-1, 0, 1000, 5000, 1_000_000]
    for t in tests:
        print(generate_random_above(t))

if __name__ == "__main__":
    main()