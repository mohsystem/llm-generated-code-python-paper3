from typing import List

class MountainArray:
    def __init__(self, data: List[int]) -> None:
        if data is None:
            raise ValueError("data cannot be None")
        self._data = list(data)
        self._calls = 0

    def get(self, k: int) -> int:
        if k < 0 or k >= len(self._data):
            raise IndexError("Index out of bounds")
        self._calls += 1
        return self._data[k]

    def length(self) -> int:
        return len(self._data)

    def calls(self) -> int:
        return self._calls

def find_in_mountain_array_with_raw_array(array: List[int], target: int) -> int:
    m = MountainArray(array)
    return find_in_mountain_array(target, m)

def find_in_mountain_array(target: int, mountain_arr: MountainArray) -> int:
    n = mountain_arr.length()
    if n < 3:
        return -1

    peak = _find_peak(mountain_arr)
    left = _bin_search_asc(mountain_arr, 0, peak, target)
    if left != -1:
        return left
    return _bin_search_desc(mountain_arr, peak + 1, n - 1, target)

def _find_peak(m: MountainArray) -> int:
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

def _bin_search_asc(m: MountainArray, lo: int, hi: int, target: int) -> int:
    ans = -1
    while lo <= hi:
        mid = lo + (hi - lo) // 2
        val = m.get(mid)
        if val == target:
            ans = mid
            hi = mid - 1
        elif val < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return ans

def _bin_search_desc(m: MountainArray, lo: int, hi: int, target: int) -> int:
    ans = -1
    while lo <= hi:
        mid = lo + (hi - lo) // 2
        val = m.get(mid)
        if val == target:
            ans = mid
            hi = mid - 1
        elif val < target:
            hi = mid - 1
        else:
            lo = mid + 1
    return ans

if __name__ == "__main__":
    tests = [
        ([1,2,3,4,5,3,1], 3),
        ([0,1,2,4,2,1], 3),
        ([0,5,3,1], 1),
        ([1,2,3,4,5,4,3,2,1], 9),
        ([0,1,0], 0),
    ]
    for arr, t in tests:
        print(find_in_mountain_array_with_raw_array(arr, t))