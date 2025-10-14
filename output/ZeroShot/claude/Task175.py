
class MountainArray:
    def __init__(self, arr):
        self.arr = arr
    
    def get(self, index):
        return self.arr[index]
    
    def length(self):
        return len(self.arr)

def findInMountainArray(target, mountain_arr):
    length = mountain_arr.length()
    
    # Find peak index
    peak_index = find_peak(mountain_arr, length)
    
    # Search in ascending part
    result = binary_search_ascending(mountain_arr, target, 0, peak_index)
    if result != -1:
        return result
    
    # Search in descending part
    return binary_search_descending(mountain_arr, target, peak_index + 1, length - 1)

def find_peak(mountain_arr, length):
    left, right = 0, length - 1
    while left < right:
        mid = left + (right - left) // 2
        if mountain_arr.get(mid) < mountain_arr.get(mid + 1):
            left = mid + 1
        else:
            right = mid
    return left

def binary_search_ascending(mountain_arr, target, left, right):
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

def binary_search_descending(mountain_arr, target, left, right):
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
    # Test case 1
    arr1 = [1, 2, 3, 4, 5, 3, 1]
    ma1 = MountainArray(arr1)
    print("Test 1:", findInMountainArray(3, ma1))  # Expected: 2
    
    # Test case 2
    arr2 = [0, 1, 2, 4, 2, 1]
    ma2 = MountainArray(arr2)
    print("Test 2:", findInMountainArray(3, ma2))  # Expected: -1
    
    # Test case 3
    arr3 = [1, 2, 3, 4, 5, 3, 1]
    ma3 = MountainArray(arr3)
    print("Test 3:", findInMountainArray(5, ma3))  # Expected: 4
    
    # Test case 4
    arr4 = [1, 5, 2]
    ma4 = MountainArray(arr4)
    print("Test 4:", findInMountainArray(2, ma4))  # Expected: 2
    
    # Test case 5
    arr5 = [1, 2, 3, 4, 5, 3, 1]
    ma5 = MountainArray(arr5)
    print("Test 5:", findInMountainArray(1, ma5))  # Expected: 0
