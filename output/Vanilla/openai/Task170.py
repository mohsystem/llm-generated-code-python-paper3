from bisect import bisect_left, bisect_right

def count_range_sum(nums, lower, upper):
    s = 0
    pref = [0]
    for v in nums:
        s += v
        pref.append(s)
    vals = sorted(set(pref))
    n = len(vals)
    BIT = [0] * (n + 2)

    def add(idx, delta):
        while idx <= n:
            BIT[idx] += delta
            idx += idx & -idx

    def sum_bit(idx):
        res = 0
        while idx > 0:
            res += BIT[idx]
            idx -= idx & -idx
        return res

    ans = 0
    add(bisect_left(vals, 0) + 1, 1)
    for i in range(1, len(pref)):
        s = pref[i]
        l = bisect_left(vals, s - upper) + 1
        r = bisect_right(vals, s - lower)
        ans += sum_bit(r) - sum_bit(l - 1)
        add(bisect_left(vals, s) + 1, 1)
    return ans

if __name__ == "__main__":
    tests = [
        ([-2,5,-1], -2, 2),
        ([0], 0, 0),
        ([1,-1,2,-2,3], 1, 3),
        ([0,0,0], 0, 0),
        ([2,-2,2,-2], -1, 1),
    ]
    for nums, lower, upper in tests:
        print(count_range_sum(nums, lower, upper))