def longestRun(arr):
    if arr is None or len(arr) == 0:
        return 0
    max_len = 1
    cur_len = 1
    dirn = 0  # 1 for increasing, -1 for decreasing, 0 unknown

    for i in range(1, len(arr)):
        diff = arr[i] - arr[i - 1]
        if diff == 1:
            if dirn in (1, 0):
                cur_len += 1
            else:
                cur_len = 2
            dirn = 1
        elif diff == -1:
            if dirn in (-1, 0):
                cur_len += 1
            else:
                cur_len = 2
            dirn = -1
        else:
            cur_len = 1
            dirn = 0
        if cur_len > max_len:
            max_len = cur_len
    return max_len


if __name__ == "__main__":
    print(longestRun([1, 2, 3, 5, 6, 7, 8, 9]))  # 5
    print(longestRun([1, 2, 3, 10, 11, 15]))     # 3
    print(longestRun([5, 4, 2, 1]))              # 2
    print(longestRun([3, 5, 7, 10, 15]))         # 1
    print(longestRun([7]))                       # 1