def odd_or_even(arr):
    if arr is None or len(arr) == 0:
        return "even"
    parity = 0
    for x in arr:
        parity ^= (x & 1)
    return "odd" if parity else "even"

if __name__ == "__main__":
    tests = [
        [0],
        [0, 1, 4],
        [0, -1, -5],
        [],
        [2, 2, 2, 3],
    ]
    for t in tests:
        print(f"{t} -> {odd_or_even(t)}")