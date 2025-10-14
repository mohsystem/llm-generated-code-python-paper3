from typing import Tuple

MAX_LEN = 1_000_000

def largest_product(digits: str, span: int) -> Tuple[bool, int]:
    if not isinstance(digits, str):
        return (False, -1)
    n = len(digits)
    if n > MAX_LEN:
        return (False, -1)
    if not isinstance(span, int) or span < 0 or span > n:
        return (False, -1)
    if any(c < '0' or c > '9' for c in digits):
        return (False, -1)

    if span == 0:
        return (True, 1)
    if span == 1:
        return (True, max(int(c) for c in digits))

    max_prod = 0
    for i in range(0, n - span + 1):
        prod = 1
        zero_found = False
        for j in range(i, i + span):
            d = ord(digits[j]) - 48
            if d == 0:
                prod = 0
                zero_found = True
                break
            prod *= d
        if not zero_found:
            # nothing special
            pass
        if prod > max_prod:
            max_prod = prod
    return (True, max_prod)

def run_test(d: str, s: int) -> None:
    ok, val = largest_product(d, s)
    print(val if ok else "ERROR")

if __name__ == "__main__":
    # Test 1: Example
    run_test("63915", 3)

    # Test 2: Contains zeros
    run_test("10203", 2)

    # Test 3: Long sequence with span 6
    long_seq = "73167176531330624919225119674426574742355349194934"
    run_test(long_seq, 6)

    # Test 4: Span 0
    run_test("12345", 0)

    # Test 5: 25 nines, span 21
    run_test("9" * 25, 21)