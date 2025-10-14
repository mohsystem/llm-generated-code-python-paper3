from typing import List, Tuple

def gcd(a: int, b: int) -> int:
    if a == 0:
        return abs(b)
    if b == 0:
        return abs(a)
    while b != 0:
        a, b = b, a % b
    return abs(a)

def main() -> None:
    tests: List[Tuple[int, int]] = [
        (48, 18),
        (0, 5),
        (0, 0),
        (-24, 60),
        (13, 17),
    ]
    for x, y in tests:
        print(f"gcd({x}, {y}) = {gcd(x, y)}")

if __name__ == "__main__":
    main()