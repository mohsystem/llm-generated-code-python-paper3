def merge_sorted_arrays(a, b):
    if a is None:
        a = []
    if b is None:
        b = []
    i = j = 0
    res = []
    while i < len(a) and j < len(b):
        if a[i] <= b[j]:
            res.append(a[i])
            i += 1
        else:
            res.append(b[j])
            j += 1
    res.extend(a[i:])
    res.extend(b[j:])
    return res

def main():
    testsA = [
        [1, 3, 5],
        [],
        [1, 1, 2, 2],
        [-5, -3, 0, 2],
        [1, 2, 7, 8, 9]
    ]
    testsB = [
        [2, 4, 6],
        [1, 2, 3],
        [1, 2, 2, 3],
        [-4, -1, 3],
        [3, 4]
    ]
    for t in range(5):
        print(merge_sorted_arrays(testsA[t], testsB[t]))

if __name__ == "__main__":
    main()