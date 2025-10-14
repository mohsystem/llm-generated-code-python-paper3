
class MountainArray:
    def __init__(self, arr):
        if not isinstance(arr, list):
            raise TypeError("Array must be a list")
        self._arr = arr
    
    def get(self, index: int) -> int:
        if not isinstance(index, int):
            raise TypeError("Index must be an integer")
        if index < 0 or index >= len(self._arr):
            raise IndexError("Index out of bounds")
        return self._arr[index]
    
    def length(self) -> int:
        return len(self._arr)


def findInMountainArray(target: int, mountain_arr: 'MountainArray') -> int:
    if mountain_arr is None:
        return -1
    
    length = mountain_arr.length()
    if length < 3:
        return -1
    
    peak_index = find_peak(mountain_arr, length)
    
    result = binary_search_ascending(mountain_arr, target, 0, peak_index)
    if result != -1:
        return result
    
    return binary_search_descending(mountain_arr, target, peak_index + 1, length - 1)


def find_peak(mountain_arr: 'MountainArray', length: int) -> int:
    left = 0
    right = length - 1
    
    while left < right:
        mid = left + (right - left) // 2
        mid_val = mountain_arr.get(mid)
        next_val = mountain_arr.get(mid + 1)
        
        if mid_val < next_val:
            left = mid + 1
        else:
            right = mid
    
    return left


def binary_search_ascending(mountain_arr: 'MountainArray', target: int, left: int, right: int) -> int:
    while left <= right:
        mid = left + (right - left) // 2
        mid_val = mountain_arr.get(mid)
        
        if mid_val == target:
            return mid
        elif mid_val < target:
            left = mid + 1
        else:
            right = mid - 1
    
    return -1


def binary_search_descending(mountain_arr: 'MountainArray', target: int, left: int, right: int) -> int:
    while left <= right:
        mid = left + (right - left) // 2
        mid_val = mountain_arr.get(mid)
        
        if mid_val == target:
            return mid
        elif mid_val > target:
            left = mid + 1
        else:
            right = mid - 1
    
    return -1


if __name__ == "__main__":
    test_arrays = [
        [1, 2, 3, 4, 5, 3, 1],
        [0, 1, 2, 4, 2, 1],
        [1, 5, 2],
        [0, 5, 3, 1],
        [1, 2, 3, 5, 3]
    ]
    targets = [3, 3, 2, 1, 3]
    expected = [2, -1, 2, 3, 2]
    
    for i in range(len(test_arrays)):
        mountain_arr = MountainArray(test_arrays[i])
        result = findInMountainArray(targets[i], mountain_arr)
        status = "PASS" if result == expected[i] else "FAIL"
        print(f"Test {i + 1}: target={targets[i]}, result={result}, expected={expected[i]}, {status}")
