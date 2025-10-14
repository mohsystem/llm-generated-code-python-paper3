from typing import List

def persistence(num: int) -> int:
    """
    Returns multiplicative persistence of a non-negative integer.
    Returns -1 for invalid (negative) input.
    """
    if not isinstance(num, int):
        raise TypeError("num must be an int")
    if num < 0:
        return -1
    count = 0
    while num >= 10:
        prod = 1
        n = num
        while n > 0:
            prod *= n % 10
            n //= 10
        num = prod
        count += 1
    return count

def main() -> None:
    tests: List[int] = [39, 999, 4, 25, 444]
    for t in tests:
        print(f"persistence({t}) = {persistence(t)}")

if __name__ == "__main__":
    main()