from typing import List, Optional

class MountainArray:
    def __init__(self, arr: List[int], max_gets: Optional[int] = None) -> None:
        self._arr = list(arr) if arr is not None else []
        self._get_count = 0
        self._max_gets = max_gets if (max_gets is None or max_gets >= 1) else 1

    def get(self, k: int) -> int:
        if k < 0 or k >= len(self._arr):
            raise IndexError("Index out of bounds")
        if self._max_gets is not None:
            if self._get_count + 1 > self._max_gets:
                raise RuntimeError("Exceeded get limit")
        self._get_count += 1
        return self._arr[k]

    def length(self) -> int:
        return len(self._arr)

def findInMountainArray(target: int, mountain_arr: MountainArray) -> int:
    if mountain_arr is None:
        return -1
    n = mountain_arr.length()
    if n < 3:
        return -1

    def find_peak(m: MountainArray) -> int:
        lo, hi = 0, m.length() - 1
        while lo < hi:
            mid = lo + (hi - lo) // 2
            a = m.get(mid)
            b = m.get(mid + 1)
            if a < b:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def bin_search_asc(m: MountainArray, lo: int, hi: int, t: int) -> int:
        res = -1
        while lo <= hi:
            mid = lo + (hi - lo) // 2
            val = m.get(mid)
            if val == t:
                res = mid
                hi = mid - 1
            elif val < t:
                lo = mid + 1
            else:
                hi = mid - 1
        return res

    def bin_search_desc(m: MountainArray, lo: int, hi: int, t: int) -> int:
        res = -1
        while lo <= hi:
            mid = lo + (hi - lo) // 2
            val = m.get(mid)
            if val == t:
                res = mid
                hi = mid - 1
            elif val > t:
                lo = mid + 1
            else:
                hi = mid - 1
        return res

    peak = find_peak(mountain_arr)
    left = bin_search_asc(mountain_arr, 0, peak, target)
    if left != -1:
        return left
    return bin_search_desc(mountain_arr, peak + 1, n - 1, target)

if __name__ == "__main__":
    tests = [
        ([1, 2, 3, 4, 5, 3, 1], 3),
        ([0, 1, 2, 4, 2, 1], 3),
        ([0, 5, 3, 1], 1),
        ([1, 5, 2], 2),
        ([1, 2, 3, 4, 5, 6, 7, 6, 5, 4, 3, 2, 1], 7),
    ]
    for arr, target in tests:
        m = MountainArray(arr, max_gets=1000)
        print(findInMountainArray(target, m))