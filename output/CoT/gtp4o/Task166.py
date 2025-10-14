def posNegSort(arr):
    if arr is None:
        return []
    positives = sorted([x for x in arr if x > 0])
    it = iter(positives)
    result = []
    for x in arr:
        result.append(next(it) if x > 0 else x)
    return result

if __name__ == "__main__":
    tests = [
        [6, 3, -2, 5, -8, 2, -2],
        [6, 5, 4, -1, 3, 2, -1, 1],
        [-5, -5, -5, -5, 7, -5],
        [],
        [5, -1, -2, 4, 3],
    ]
    for t in tests:
        print(posNegSort(t))