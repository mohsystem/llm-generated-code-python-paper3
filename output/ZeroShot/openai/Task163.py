class Task163:
    @staticmethod
    def longestRun(arr):
        if arr is None or len(arr) == 0:
            return 0
        n = len(arr)
        max_len = 1
        cur_len = 1
        dirn = 0  # 1 inc, -1 dec, 0 none
        for i in range(1, n):
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
                if cur_len > max_len:
                    max_len = cur_len
                cur_len = 1
                dirn = 0
            if cur_len > max_len:
                max_len = cur_len
        if cur_len > max_len:
            max_len = cur_len
        return max_len


if __name__ == "__main__":
    tests = [
        [1, 2, 3, 5, 6, 7, 8, 9],
        [1, 2, 3, 10, 11, 15],
        [5, 4, 2, 1],
        [3, 5, 7, 10, 15],
        [1],
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} Input: {t} -> Longest Run: {Task163.longestRun(t)}")