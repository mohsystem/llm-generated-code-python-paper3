def factorial(n):
    if n < 0:
        raise ValueError("Negative input not allowed")
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result

if __name__ == "__main__":
    tests = [0, 1, 5, 10, 20]
    for t in tests:
        print(f"{t}! = {factorial(t)}")