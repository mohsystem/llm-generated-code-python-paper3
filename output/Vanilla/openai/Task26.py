def find_odd(arr):
    x = 0
    for v in arr:
        x ^= v
    return x

if __name__ == "__main__":
    tests = [
        [7],
        [0],
        [1, 1, 2],
        [0, 1, 0, 1, 0],
        [1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1],
    ]
    for t in tests:
        print(find_odd(t))