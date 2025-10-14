def narcissistic(n: int) -> bool:
    if n <= 0:
        return False
    digits = 0
    temp = n
    while temp > 0:
        digits += 1
        temp //= 10
    total = 0
    temp = n
    while temp > 0:
        d = temp % 10
        total += d ** digits
        temp //= 10
    return total == n

if __name__ == "__main__":
    tests = [153, 1652, 7, 370, 9474]
    for t in tests:
        print(f"{t} -> {narcissistic(t)}")