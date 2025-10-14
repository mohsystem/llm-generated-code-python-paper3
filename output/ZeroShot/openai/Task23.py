from math import isqrt

def find_nb(m: int) -> int:
    if m <= 0:
        return -1
    k = isqrt(m)
    if k * k != m:
        return -1
    d = 1 + 8 * k
    sd = isqrt(d)
    if sd * sd != d:
        return -1
    n = (sd - 1) // 2
    t = (n // 2) * (n + 1) if n % 2 == 0 else n * ((n + 1) // 2)
    return n if t == k else -1

if __name__ == "__main__":
    tests = [
        1071225,          # -> 45
        91716553919377,   # -> -1
        4183059834009,    # -> 2022
        1,                # -> 1
        0                 # -> -1
    ]
    for m in tests:
        print(f"findNb({m}) = {find_nb(m)}")