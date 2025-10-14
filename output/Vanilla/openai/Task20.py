def dig_pow(n: int, p: int) -> int:
    total = sum(int(d) ** (p + i) for i, d in enumerate(str(n)))
    return total // n if total % n == 0 else -1

if __name__ == "__main__":
    print(dig_pow(89, 1))      # 1
    print(dig_pow(92, 1))      # -1
    print(dig_pow(695, 2))     # 2
    print(dig_pow(46288, 3))   # 51
    print(dig_pow(135, 1))     # 1