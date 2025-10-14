from typing import List

def longest_run(arr: List[int]) -> int:
    if arr is None or len(arr) == 0:
        return 0
    if len(arr) == 1:
        return 1
    best = 1
    curr = 1
    dir_val = 0  # 0 none, 1 increasing, -1 decreasing
    for i in range(1, len(arr)):
        diff = arr[i] - arr[i - 1]
        if (diff == 1 or diff == -1) and diff == dir_val:
            curr += 1
        elif diff == 1 or diff == -1:
            curr = 2
            dir_val = diff
        else:
            curr = 1
            dir_val = 0
        if curr > best:
            best = curr
    return best

if __name__ == "__main__":
    tests = [
        [1, 2, 3, 5, 6, 7, 8, 9],
        [1, 2, 3, 10, 11, 15],
        [5, 4, 2, 1],
        [3, 5, 7, 10, 15],
        []
    ]
    for t in tests:
        print(f"{t} -> {longest_run(t)}")