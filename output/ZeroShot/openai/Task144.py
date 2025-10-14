def merge_sorted(a, b):
    a = [] if a is None else list(a)
    b = [] if b is None else list(b)
    i = j = 0
    la, lb = len(a), len(b)
    result = []

    while i < la and j < lb:
        if a[i] <= b[j]:
            result.append(a[i])
            i += 1
        else:
            result.append(b[j])
            j += 1

    if i < la:
        result.extend(a[i:])
    if j < lb:
        result.extend(b[j:])

    return result


if __name__ == "__main__":
    tests = [
        ([], []),
        ([1, 3, 5], [2, 4, 6]),
        ([], [7, 8]),
        ([-5, -1, 0, 2], [-4, -3, 3, 10]),
        ([1, 2, 2, 3], [2, 2, 4, 5]),
    ]
    for a, b in tests:
        print(merge_sorted(a, b))