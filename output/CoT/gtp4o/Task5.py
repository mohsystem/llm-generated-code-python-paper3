def persistence(num: int) -> int:
    if not isinstance(num, int):
        raise TypeError("num must be an int")
    if num < 0:
        raise ValueError("num must be non-negative")
    steps = 0
    n = num
    while n >= 10:
        prod = 1
        while n > 0:
            prod *= n % 10
            n //= 10
        n = prod
        steps += 1
    return steps

if __name__ == "__main__":
    tests = [39, 999, 4, 25, 77]
    for t in tests:
        print(f"persistence({t}) = {persistence(t)}")