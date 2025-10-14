from typing import List

class MountainArray:
    def get(self, index: int) -> int:
        raise NotImplementedError

    def length(self) -> int:
        raise NotImplementedError

    def get_call_count(self) -> int:
        raise NotImplementedError

class ArrayMountain(MountainArray):
    def __init__(self, arr: List[int]) -> None:
        if arr is None:
            raise ValueError("Array cannot be None")
        self._data: List[int] = list(arr)
        self._calls: int = 0

    def get(self, index: int) -> int:
        if index < 0 or index >= len(self._data):
            raise IndexError("Index out of bounds")
        self._calls += 1
        return self._data[index]

    def length(self) -> int:
        return len(self._data)

    def get_call_count(self) -> int:
        return self._calls

def find_in_mountain_array(target: int, mountain_arr: MountainArray) -> int:
    if mountain_arr is None:
        return -1
    n = mountain_arr.length()
    if n < 3:
        return -1

    def find_peak(arr: MountainArray) -> int:
        l, r = 0, arr.length() - 1
        while l < r:
            m = l + (r - l) // 2
            a = arr.get(m)
            b = arr.get(m + 1)
            if a < b:
                l = m + 1
            else:
                r = m
        return l

    def bin_asc(arr: MountainArray, lo: int, hi: int, tgt: int) -> int:
        l, r = lo, hi
        while l <= r:
            m = l + (r - l) // 2
            v = arr.get(m)
            if v == tgt:
                return m
            if v < tgt:
                l = m + 1
            else:
                r = m - 1
        return -1

    def bin_desc(arr: MountainArray, lo: int, hi: int, tgt: int) -> int:
        l, r = lo, hi
        while l <= r:
            m = l + (r - l) // 2
            v = arr.get(m)
            if v == tgt:
                return m
            if v < tgt:
                r = m - 1
            else:
                l = m + 1
        return -1

    peak = find_peak(mountain_arr)
    left = bin_asc(mountain_arr, 0, peak, target)
    if left != -1:
        return left
    return bin_desc(mountain_arr, peak + 1, n - 1, target)

def _run_test(array: List[int], target: int, expected: int) -> None:
    ma = ArrayMountain(array)
    res = find_in_mountain_array(target, ma)
    print(f"Array: {array}, target={target} -> result={res}, expected={expected}, getCalls={ma.get_call_count()}")

if __name__ == "__main__":
    _run_test([1, 2, 3, 4, 5, 3, 1], 3, 2)       # Example 1
    _run_test([0, 1, 2, 4, 2, 1], 3, -1)         # Example 2
    _run_test([1, 3, 5, 7, 9, 6, 4, 2], 1, 0)    # Target at start
    _run_test([2, 5, 9, 12, 10, 7, 2], 7, 5)     # Target on right
    _run_test([0, 2, 5, 10, 9, 8, 1], 10, 3)     # Target at peak