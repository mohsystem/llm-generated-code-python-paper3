from math import isqrt

def find_nb(m: int) -> int:
    if not isinstance(m, int):
        return -1
    if m < 0:
        return -1
    if m == 0:
        return 0

    s = isqrt(m)
    if s * s != m:
        return -1

    disc = 1 + 8 * s
    r = isqrt(disc)
    if r * r != disc:
        return -1

    n = (r - 1) // 2
    if n * (n + 1) // 2 == s:
        return n
    return -1

if __name__ == "__main__":
    tests = [
        1071225,          # expected 45
        91716553919377,   # expected -1
        1,                # expected 1
        4183059834009,    # expected 2022
        0                 # expected 0
    ]
    for m in tests:
        print(find_nb(m))