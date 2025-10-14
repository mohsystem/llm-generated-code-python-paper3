def two_sum(numbers, target):
    seen = {}
    for i, num in enumerate(numbers):
        comp = target - num
        if comp in seen:
            return [seen[comp], i]
        if num not in seen:
            seen[num] = i
    return []

def _print_result(res):
    if len(res) == 2:
        print("{" + str(res[0]) + ", " + str(res[1]) + "}")
    else:
        print("{}")

if __name__ == "__main__":
    tests = [
        ([1, 2, 3], 4),
        ([3, 2, 4], 6),
        ([2, 7, 11, 15], 9),
        ([3, 3], 6),
        ([0, -1, 2, -3, 5], -1),
    ]
    for arr, target in tests:
        res = two_sum(arr, target)
        _print_result(res)