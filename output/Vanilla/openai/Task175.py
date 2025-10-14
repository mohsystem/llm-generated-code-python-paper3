from typing import List

class MountainArray:
    def get(self, index: int) -> int:
        raise NotImplementedError
    def length(self) -> int:
        raise NotImplementedError

class SimpleMountainArray(MountainArray):
    def __init__(self, arr: List[int]):
        self.arr = arr
        self.calls = 0
    def get(self, index: int) -> int:
        self.calls += 1
        return self.arr[index]
    def length(self) -> int:
        return len(self.arr)

def findInMountainArray(target: int, mountainArr: MountainArray) -> int:
    n = mountainArr.length()
    peak = _find_peak(mountainArr, n)
    left = _binary_search_asc(mountainArr, 0, peak, target)
    if left != -1:
        return left
    return _binary_search_desc(mountainArr, peak + 1, n - 1, target)

def _find_peak(m: MountainArray, n: int) -> int:
    l, r = 0, n - 1
    while l < r:
        mid = (l + r) // 2
        if m.get(mid) < m.get(mid + 1):
            l = mid + 1
        else:
            r = mid
    return l

def _binary_search_asc(m: MountainArray, l: int, r: int, target: int) -> int:
    while l <= r:
        mid = (l + r) // 2
        val = m.get(mid)
        if val == target:
            return mid
        if val < target:
            l = mid + 1
        else:
            r = mid - 1
    return -1

def _binary_search_desc(m: MountainArray, l: int, r: int, target: int) -> int:
    while l <= r:
        mid = (l + r) // 2
        val = m.get(mid)
        if val == target:
            return mid
        if val < target:
            r = mid - 1
        else:
            l = mid + 1
    return -1

if __name__ == "__main__":
    arrays = [
        [1,2,3,4,5,3,1],
        [0,1,2,4,2,1],
        [0,5,3,1],
        [0,2,4,5,3,1],
        [0,2,4,5,3,1],
    ]
    targets = [3, 3, 1, 0, 1]
    for arr, t in zip(arrays, targets):
        sma = SimpleMountainArray(arr)
        print(findInMountainArray(t, sma))