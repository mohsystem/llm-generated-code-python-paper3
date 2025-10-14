def largest_product(input_str: str, span: int) -> int:
    if span < 0:
        return 0
    if span == 0:
        return 1
    if input_str is None:
        return 0
    n = len(input_str)
    if span > n:
        return 0
    if any(ch < '0' or ch > '9' for ch in input_str):
        return 0
    best = 0
    for i in range(n - span + 1):
        prod = 1
        for ch in input_str[i:i+span]:
            d = ord(ch) - 48
            prod *= d
            if prod == 0:
                break
        if prod > best:
            best = prod
    return best

if __name__ == "__main__":
    print(largest_product("63915", 3))   # 162
    print(largest_product("12345", 2))   # 20
    print(largest_product("000123", 2))  # 6
    print(largest_product("", 0))        # 1
    print(largest_product("99999", 5))   # 59049