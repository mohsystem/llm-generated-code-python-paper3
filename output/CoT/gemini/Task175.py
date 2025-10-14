# """
# This is MountainArray's API interface.
# You should not implement it, or speculate about its implementation
# """
#class MountainArray:
#    def get(self, index: int) -> int:
#    def length(self) -> int:

# Mock implementation for local testing
class MountainArray:
    def __init__(self, arr):
        self._arr = arr
    
    def get(self, index: int) -> int:
        return self._arr[index]
    
    def length(self) -> int:
        return len(self._arr)

class Task175:
    def findInMountainArray(self, target: int, mountain_arr: 'MountainArray') -> int:
        length = mountain_arr.length()
        
        # 1. Find the index of the peak element
        low, high = 0, length - 1
        peak_index = -1
        while low < high:
            mid = low + (high - low) // 2
            if mountain_arr.get(mid) < mountain_arr.get(mid + 1):
                low = mid + 1
            else:
                high = mid
        peak_index = low
        
        # 2. Search in the strictly increasing part
        low, high = 0, peak_index
        while low <= high:
            mid = low + (high - low) // 2
            mid_val = mountain_arr.get(mid)
            if mid_val == target:
                return mid
            elif mid_val < target:
                low = mid + 1
            else:
                high = mid - 1
        
        # 3. If not found, search in the strictly decreasing part
        low, high = peak_index + 1, length - 1
        while low <= high:
            mid = low + (high - low) // 2
            mid_val = mountain_arr.get(mid)
            if mid_val == target:
                return mid
            elif mid_val > target: # Note the change in logic
                low = mid + 1
            else:
                high = mid - 1
                
        # 4. Target not found
        return -1

if __name__ == '__main__':
    solution = Task175()

    # Test Case 1
    mountain_arr1 = MountainArray([1, 2, 3, 4, 5, 3, 1])
    target1 = 3
    print(f"Test Case 1: {solution.findInMountainArray(target1, mountain_arr1)}") # Expected: 2

    # Test Case 2
    mountain_arr2 = MountainArray([0, 1, 2, 4, 2, 1])
    target2 = 3
    print(f"Test Case 2: {solution.findInMountainArray(target2, mountain_arr2)}") # Expected: -1
    
    # Test Case 3
    mountain_arr3 = MountainArray([1, 5, 2])
    target3 = 2
    print(f"Test Case 3: {solution.findInMountainArray(target3, mountain_arr3)}") # Expected: 2
    
    # Test Case 4
    mountain_arr4 = MountainArray([1, 2, 3, 4, 5, 6, 7])
    target4 = 5
    print(f"Test Case 4: {solution.findInMountainArray(target4, mountain_arr4)}") # Expected: 4
    
    # Test Case 5
    mountain_arr5 = MountainArray([7, 6, 5, 4, 3, 2, 1])
    target5 = 5
    print(f"Test Case 5: {solution.findInMountainArray(target5, mountain_arr5)}") # Expected: 2