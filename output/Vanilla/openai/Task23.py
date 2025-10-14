def findNb(m: int) -> int:
    if m < 0:
        return -1
    n = 0
    while m > 0:
        n += 1
        m -= n ** 3
    return n if m == 0 else -1

if __name__ == "__main__":
    tests = [
        1071225,          # 45
        91716553919377,   # -1
        4183059834009,    # 2022
        0,                # 0
        135440716410000   # 4824
    ]
    for m in tests:
        print(findNb(m))