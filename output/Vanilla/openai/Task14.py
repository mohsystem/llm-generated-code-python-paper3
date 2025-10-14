def find_even_index(arr):
    total = sum(arr)
    left = 0
    for i, v in enumerate(arr):
        right = total - left - v
        if left == right:
            return i
        left += v
    return -1


if __name__ == "__main__":
    tests = [
        [1, 2, 3, 4, 3, 2, 1],
        [1, 100, 50, -51, 1, 1],
        [20, 10, -80, 10, 10, 15, 35],
        [1, 2, 3, 4, 5, 6],
        [0, 0, 0, 0],
    ]
    for t in tests:
        print(f"{t} -> {find_even_index(t)}")