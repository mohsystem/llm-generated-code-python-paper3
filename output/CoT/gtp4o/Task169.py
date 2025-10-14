def count_smaller(nums):
    n = len(nums)
    res = [0] * n
    if n == 0:
        return res
    # Coordinate compression
    uniq = sorted(set(nums))
    index = {v: i + 1 for i, v in enumerate(uniq)}  # 1-based for BIT
    # Fenwick Tree
    size = len(uniq) + 2
    bit = [0] * size

    def update(i, delta):
        while i < size:
            bit[i] += delta
            i += i & -i

    def query(i):
        s = 0
        while i > 0:
            s += bit[i]
            i -= i & -i
        return s

    for i in range(n - 1, -1, -1):
        idx = index[nums[i]]
        res[i] = query(idx - 1)
        update(idx, 1)
    return res

if __name__ == "__main__":
    # 5 test cases
    tests = [
        [5, 2, 6, 1],
        [-1],
        [-1, -1],
        [1, 2, 3, 4],
        [4, 3, 2, 1]
    ]
    for t in tests:
        print(count_smaller(t))