# Task183 - Python implementation
# Chain-of-Through secure coding process:
# 1) Problem understanding: compute the largest product of any contiguous series of a given span in a digit string.
# 2) Security requirements: validate inputs (type, negative span, non-digits, span bounds), avoid unsafe operations.
# 3) Secure coding generation: straightforward O(n*span) algorithm; handle span==0; short-circuit on zero digit.
# 4) Code review: ensure bounds and checks are correct; Python ints are arbitrary precision.
# 5) Secure code output: final function returns deterministic results; includes 5 test cases.

from typing import Optional

def largest_product(digits: Optional[str], span: int) -> int:
    if span < 0:
        return 0
    if span == 0:
        return 1
    if digits is None:
        return 0
    n = len(digits)
    if span > n:
        return 0
    if any(c < '0' or c > '9' for c in digits):
        return 0

    max_product = 0
    for i in range(0, n - span + 1):
        product = 1
        zero_found = False
        for j in range(i, i + span):
            d = ord(digits[j]) - 48
            if d == 0:
                product = 0
                zero_found = True
                break
            product *= d
        if product > max_product:
            max_product = product
        if max_product == 0 and zero_found and span == 1:
            # trivial early exit case; not necessary but harmless
            pass
    return max_product

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ("63915", 3),
        ("1234567890", 2),
        ("0000", 2),
        ("99999", 5),
        ("", 0),
    ]
    for idx, (s, sp) in enumerate(tests, 1):
        print(f"Test {idx}: largest_product({s!r}, {sp}) = {largest_product(s, sp)}")