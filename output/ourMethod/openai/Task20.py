from typing import List, Tuple

def dig_pow(n: int, p: int) -> int:
    if not isinstance(n, int) or not isinstance(p, int):
        return -1
    if n <= 0 or p <= 0:
        return -1
    s = str(n)
    total = 0
    exp = p
    for ch in s:
        if ch < '0' or ch > '9':
            return -1
        d = ord(ch) - ord('0')
        total += pow(d, exp)
        exp += 1
    if total % n == 0:
        return total // n
    return -1

if __name__ == "__main__":
    tests: List[Tuple[int, int]] = [
        (89, 1),
        (92, 1),
        (695, 2),
        (46288, 3),
        (1, 1),
    ]
    for n, p in tests:
        print(f"dig_pow({n}, {p}) = {dig_pow(n, p)}")