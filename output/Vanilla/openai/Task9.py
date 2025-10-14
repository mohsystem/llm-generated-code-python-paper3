def odd_or_even(arr):
    if not arr:
        return "even"
    parity = 0
    for x in arr:
        parity ^= (abs(x) & 1)
    return "odd" if parity else "even"


if __name__ == "__main__":
    tests = [
        [],
        [0],
        [0, 1, 4],
        [0, -1, -5],
        [1, 2, 3, 4, 5],
    ]
    for t in tests:
        print(odd_or_even(t))