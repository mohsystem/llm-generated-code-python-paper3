# Chain-of-Through process:
# 1) Problem understanding: Compute factorial of a non-negative integer.
# 2) Security requirements: Validate input, handle big integers (Python int is unbounded).
# 3) Secure coding generation: Iterative, avoids recursion.
# 4) Code review: Handle n=0, n=1; return consistent types.
# 5) Secure code output: Final with 5 test cases.

def compute_factorial(n: int) -> str:
    if not isinstance(n, int) or n < 0:
        return "INVALID"
    result = 1
    for i in range(2, n + 1):
        result *= i
    return str(result)

if __name__ == "__main__":
    tests = [0, 1, 5, 10, 20]
    for t in tests:
        print(f"factorial({t}) = {compute_factorial(t)}")