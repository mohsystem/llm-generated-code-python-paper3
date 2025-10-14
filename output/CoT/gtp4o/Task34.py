# Chain-of-Through process:
# 1) Problem understanding: Determine if a number equals the sum of its digits each raised to the number of digits.
# 2) Security requirements: Use Python's big integers; avoid unsafe conversions.
# 3) Secure coding generation: Use integer arithmetic; no floating math issues.
# 4) Code review: Direct calculation with built-in pow ensures correctness.
# 5) Secure code output: Function returns boolean; includes 5 test cases.

def narcissistic(n: int) -> bool:
    if n <= 0:
        return False
    s = str(n)
    k = len(s)
    total = sum(pow(int(ch), k) for ch in s)
    return total == n

if __name__ == "__main__":
    tests = [153, 1652, 9474, 7, 10]
    for t in tests:
        print(f"n={t} -> {narcissistic(t)}")