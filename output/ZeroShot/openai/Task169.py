from bisect import bisect_left

def count_smaller(nums):
    if nums is None:
        return []
    n = len(nums)
    if n == 0:
        return []
    # Coordinate compression
    sorted_vals = sorted(set(nums))
    def rank(x):
        # ranks are 1-based for Fenwick
        return bisect_left(sorted_vals, x) + 1

    m = len(sorted_vals)
    bit = [0] * (m + 1)

    def update(idx, delta):
        while idx <= m:
            bit[idx] += delta
            idx += idx & -idx

    def query(idx):
        s = 0
        while idx > 0:
            s += bit[idx]
            idx -= idx & -idx
        return s

    ans = [0] * n
    for i in range(n - 1, -1, -1):
        r = rank(nums[i])
        ans[i] = query(r - 1)
        update(r, 1)
    return ans

def _print_list(a):
    print("[" + ",".join(str(x) for x in a) + "]")

if __name__ == "__main__":
    tests = [
        [5, 2, 6, 1],
        [-1],
        [-1, -1],
        [3, 2, 2, 6, 1],
        [2, 0, 1]
    ]
    for t in tests:
        res = count_smaller(t)
        print("Input: ", end=""); _print_list(t)
        print("Output: ", end=""); _print_list(res)
        print("---")