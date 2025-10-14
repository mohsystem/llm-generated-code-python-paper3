class Task163:
    @staticmethod
    def longestRun(arr):
        if arr is None or len(arr) == 0:
            return 0
        max_len = 1
        curr_len = 1
        prev_diff = None  # +1 or -1

        for i in range(1, len(arr)):
            diff = arr[i] - arr[i - 1]
            if diff in (1, -1):
                if prev_diff is not None and diff == prev_diff:
                    curr_len += 1
                else:
                    curr_len = 2
                    prev_diff = diff
            else:
                curr_len = 1
                prev_diff = None
            if curr_len > max_len:
                max_len = curr_len
        return max_len

if __name__ == "__main__":
    print(Task163.longestRun([1, 2, 3, 5, 6, 7, 8, 9]))  # 5
    print(Task163.longestRun([1, 2, 3, 10, 11, 15]))     # 3
    print(Task163.longestRun([5, 4, 2, 1]))              # 2
    print(Task163.longestRun([3, 5, 7, 10, 15]))         # 1
    print(Task163.longestRun([1, 2, 1, 0, -1]))          # 4