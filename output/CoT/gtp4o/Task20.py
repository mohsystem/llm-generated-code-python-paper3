def dig_pow(n: int, p: int) -> int:
    if n <= 0 or p <= 0:
        return -1
    total = 0
    for i, d in enumerate(map(int, str(n))):
        total += d ** (p + i)
    return total // n if total % n == 0 else -1

if __name__ == "__main__":
    tests = [
        (89, 1),
        (92, 1),
        (695, 2),
        (46288, 3),
        (1, 1),
    ]
    for n, p in tests:
        print(f"dig_pow({n}, {p}) = {dig_pow(n, p)}")