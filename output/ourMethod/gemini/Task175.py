# This is the MountainArray's API interface.
# You should not implement it, or speculate about its implementation
class MountainArray:
   def get(self, index: int) -> int:
       # This is a placeholder for the actual implementation provided by the judge.
       pass
   def length(self) -> int:
       # This is a placeholder for the actual implementation provided by the judge.
       pass

# Dummy implementation for local testing.
class MountainArrayImpl(MountainArray):
    def __init__(self, arr: list[int]):
        self._arr = arr

    def get(self, index: int) -> int:
        return self._arr[index]

    def length(self) -> int:
        return len(self._arr)

def findInMountainArray(target: int, mountain_arr: 'MountainArray') -> int:
    """
    Finds the minimum index of the target in a mountain array.
    """
    length = mountain_arr.length()
    
    # 1. Find the index of the peak element.
    low, high = 0, length - 1
    while low < high:
        mid = low + (high - low) // 2
        if mountain_arr.get(mid) < mountain_arr.get(mid + 1):
            low = mid + 1
        else:
            high = mid
    peak_index = low
    
    # 2. Search in the left (strictly increasing) part of the array.
    low, high = 0, peak_index
    while low <= high:
        mid = low + (high - low) // 2
        val = mountain_arr.get(mid)
        if val == target:
            return mid
        elif val < target:
            low = mid + 1
        else:
            high = mid - 1
            
    # 3. If not found, search in the right (strictly decreasing) part.
    low, high = peak_index + 1, length - 1
    while low <= high:
        mid = low + (high - low) // 2
        val = mountain_arr.get(mid)
        if val == target:
            return mid
        elif val < target:  # In a decreasing array, smaller values are to the right.
            high = mid - 1
        else:
            low = mid + 1
            
    # 4. Target not found in the array.
    return -1

if __name__ == '__main__':
    # Test Case 1
    mountain_arr1 = MountainArrayImpl([1, 2, 3, 4, 5, 3, 1])
    target1 = 3
    print(f"Test 1 Output: {findInMountainArray(target1, mountain_arr1)}")  # Expected: 2

    # Test Case 2
    mountain_arr2 = MountainArrayImpl([0, 1, 2, 4, 2, 1])
    target2 = 3
    print(f"Test 2 Output: {findInMountainArray(target2, mountain_arr2)}")  # Expected: -1

    # Test Case 3
    mountain_arr3 = MountainArrayImpl([1, 5, 2])
    target3 = 2
    print(f"Test 3 Output: {findInMountainArray(target3, mountain_arr3)}")  # Expected: 2

    # Test Case 4
    mountain_arr4 = MountainArrayImpl([3, 5, 3, 2, 0])
    target4 = 0
    print(f"Test 4 Output: {findInMountainArray(target4, mountain_arr4)}")  # Expected: 4

    # Test Case 5
    mountain_arr5 = MountainArrayImpl([1, 5, 2])
    target5 = 5
    print(f"Test 5 Output: {findInMountainArray(target5, mountain_arr5)}")  # Expected: 1