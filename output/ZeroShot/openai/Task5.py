def persistence(num: int) -> int:
    if not isinstance(num, int):
        raise TypeError("Input must be an integer")
    if num < 0:
        raise ValueError("Input must be non-negative")
    if num < 10:
        return 0
    count = 0
    while num >= 10:
        prod = 1
        while num > 0:
            prod *= num % 10
            if prod == 0:
                break
            num //= 10
        if num != 0:  # if we didn't fully consume num due to early break
            num = prod
        else:
            num = prod
        count += 1
    return count

if __name__ == "__main__":
    tests = [39, 999, 4, 25, 77]
    for t in tests:
        print(f"persistence({t}) = {persistence(t)}")