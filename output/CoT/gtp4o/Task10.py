# Chain-of-Through process:
# 1) Problem: Sum all integers inclusively between a and b (unordered); if equal, return either.
# 2) Security: Pure function, no I/O; use integer-safe math and divide even factor first to minimize overflow risk (Python ints are unbounded).
# 3) Secure generation: Arithmetic series formula, no iteration over range.
# 4) Review: Ensure integer division precedes large multiplication when appropriate.
# 5) Output: Provide function and 5 test cases.

def get_sum(a: int, b: int) -> int:
    if a == b:
        return a
    m, n = (a, b) if a < b else (b, a)
    count = n - m + 1
    s = m + n
    if count % 2 == 0:
        return (count // 2) * s
    else:
        return count * (s // 2)

if __name__ == "__main__":
    tests = [(1, 0), (1, 2), (0, 1), (1, 1), (-1, 2)]
    for a, b in tests:
        print(get_sum(a, b))