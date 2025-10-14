def gcd(a, b):
    a = abs(a)
    b = abs(b)
    if a == 0:
        return b
    if b == 0:
        return a
    while b != 0:
        a, b = b, a % b
    return a

if __name__ == "__main__":
    tests = [
        (54, 24),
        (0, 5),
        (17, 13),
        (-48, 18),
        (0, 0),
    ]
    for x, y in tests:
        print(f"gcd({x}, {y}) = {gcd(x, y)}")