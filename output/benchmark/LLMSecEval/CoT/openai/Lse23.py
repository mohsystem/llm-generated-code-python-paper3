# Chain-of-Through process in code generation:
# 1. Problem understanding: Generate 3 random integers > 1000, print them, compute sum and print sum and sum2.
# 2. Security requirements: Use cryptographically secure randomness and validate parameters.
# 3. Secure coding generation: Use secrets.SystemRandom and strict range checks.
# 4. Code review: Verified formatting and correct range (> 1000), consistent return.
# 5. Secure code output: Final function returns results; main executes 5 test cases.

import secrets
from typing import Tuple

def generate_and_sum(min_exclusive: int, max_inclusive: int, rng: secrets.SystemRandom = None) -> Tuple[int, int, int, int, int]:
    if max_inclusive <= min_exclusive:
        raise ValueError("max_inclusive must be greater than min_exclusive")
    r = rng or secrets.SystemRandom()
    a = r.randint(min_exclusive + 1, max_inclusive)
    b = r.randint(min_exclusive + 1, max_inclusive)
    c = r.randint(min_exclusive + 1, max_inclusive)
    s = a + b + c
    s2 = s
    return a, b, c, s, s2

def main():
    min_exclusive = 1000
    max_inclusive = 9999
    rng = secrets.SystemRandom()
    for _ in range(5):
        a, b, c, s, s2 = generate_and_sum(min_exclusive, max_inclusive, rng)
        print(f"a : {a} b : {b} c : {c} sum: {s} sum2: {s2}")

if __name__ == "__main__":
    main()