def get_sum(a: int, b: int) -> int:
    if a == b:
        return a
    lo, hi = (a, b) if a < b else (b, a)
    n = hi - lo + 1
    s = lo + hi
    if n % 2 == 0:
        n //= 2
    else:
        s //= 2
    return n * s

if __name__ == "__main__":
    tests = [
        (1, 0),
        (1, 2),
        (0, 1),
        (1, 1),
        (-1, 2),
    ]
    for a, b in tests:
        print(get_sum(a, b))