# Chain-of-Through process in code generation:
# 1) Problem understanding: find_nb returns n if sum k^3 (1..n) equals m, else -1.
# 2) Security requirements: Use integer arithmetic with isqrt to avoid floating issues.
# 3) Secure coding generation: Validate perfect square and quadratic discriminant.
# 4) Code review: No overflow in Python big ints; input checks included.
# 5) Secure code output: Final code with 5 tests.
import math

def find_nb(m: int) -> int:
    if m < 0:
        return -1
    if m == 0:
        return 0
    s = math.isqrt(m)
    if s * s != m:
        return -1
    D = 1 + 8 * s
    r = math.isqrt(D)
    if r * r != D:
        return -1
    n = (r - 1) // 2
    if ((n * (n + 1)) // 2) ** 2 != m:
        return -1
    return n

def main():
    tests = [1071225, 91716553919377, 4183059834009, 24723578342962, 135440716410000]
    for m in tests:
        print(find_nb(m))

if __name__ == "__main__":
    main()