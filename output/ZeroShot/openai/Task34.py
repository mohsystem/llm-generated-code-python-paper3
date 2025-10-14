def is_narcissistic(n: int) -> bool:
    if n <= 0:
        return False
    digits = len(str(n))
    s = 0
    t = n
    while t > 0:
        d = t % 10
        s += pow(d, digits)
        t //= 10
    return s == n

if __name__ == "__main__":
    tests = [153, 1652, 9474, 370, 9926315]
    for t in tests:
        print(is_narcissistic(t))