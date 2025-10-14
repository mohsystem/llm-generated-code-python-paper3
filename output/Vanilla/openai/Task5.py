def persistence(num: int) -> int:
    if num < 10:
        return 0
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

if __name__ == "__main__":
    tests = [39, 999, 4, 25, 777]
    for t in tests:
        print(f"persistence({t}) = {persistence(t)}")