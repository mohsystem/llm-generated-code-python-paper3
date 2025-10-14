# Chain-of-Through process:
# 1) Problem: Compute GCD of two numbers.
# 2) Security: Validate types; handle negatives and zeros.
# 3) Secure generation: Use iterative Euclidean algorithm with non-negative values.
# 4) Review: Ensure loop terminates; return non-negative.
# 5) Output: Final tested function with 5 test cases.

def gcd(a: int, b: int) -> int:
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Inputs must be integers")
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a

def main():
    tests = [
        (48, 18),
        (0, 0),
        (270, 192),
        (-24, 60),
        (13, 7),
    ]
    for x, y in tests:
        print(f"gcd({x}, {y}) = {gcd(x, y)}")

if __name__ == "__main__":
    main()