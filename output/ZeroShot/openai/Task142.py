def gcd(a: int, b: int) -> int:
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Inputs must be integers")
    if a == 0 and b == 0:
        return 0
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a

if __name__ == "__main__":
    tests = [
        (48, 18),
        (0, 0),
        (-48, 18),
        (270, 192),
        (1234567890, 9876543210),
    ]
    for x, y in tests:
        print(f"gcd({x}, {y}) = {gcd(x, y)}")