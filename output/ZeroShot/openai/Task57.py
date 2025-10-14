def factorial(n: int) -> int:
    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")
    if n < 0:
        raise ValueError("Input must be non-negative.")
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result

if __name__ == "__main__":
    test_cases = [0, 1, 5, 10, 20]
    for n in test_cases:
        try:
            print(f"factorial({n}) = {factorial(n)}")
        except (TypeError, ValueError) as e:
            print(f"factorial({n}) error: {e}")