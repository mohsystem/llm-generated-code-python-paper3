class Task169:
    @staticmethod
    def count_smaller(nums):
        n = len(nums)
        res = [0] * n
        if n == 0:
            return res
        vals = sorted(set(nums))
        idx = {v: i + 1 for i, v in enumerate(vals)}
        m = len(vals)
        bit = [0] * (m + 2)

        def update(i, delta):
            while i <= m + 1:
                bit[i] += delta
                i += i & -i

        def query(i):
            s = 0
            while i > 0:
                s += bit[i]
                i -= i & -i
            return s

        for i in range(n - 1, -1, -1):
            idv = idx[nums[i]]
            res[i] = query(idv - 1)
            update(idv, 1)
        return res

if __name__ == "__main__":
    tests = [
        [5,2,6,1],
        [-1],
        [-1,-1],
        [3,2,2,6,1],
        [1,0,2,2,5]
    ]
    for t in tests:
        print(Task169.count_smaller(t))