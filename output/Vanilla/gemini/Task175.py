# This is the MountainArray's API interface.
# You should not implement it, or speculate about its implementation
class MountainArray:
   def get(self, index: int) -> int:
       pass
   def length(self) -> int:
       pass

# Mock implementation for local testing
class MountainArrayImpl(MountainArray):
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
        peak = -1
        while low < high:
            mid = low + (high - low) // 2
            if mountain_arr.get(mid) < mountain_arr.get(mid + 1):
                low = mid + 1
            else:
                high = mid
        peak = low

        # 2. Search in the left (ascending) subarray
        low, high = 0, peak
        while low <= high:
            mid = low + (high - low) // 2
            val = mountain_arr.get(mid)
            if val < target:
                low = mid + 1
            elif val > target:
                high = mid - 1
            else:
                return mid

        # 3. Search in the right (descending) subarray
        low, high = peak + 1, length - 1
        while low <= high:
            mid = low + (high - low) // 2
            val = mountain_arr.get(mid)
            if val > target: # Note the change for descending order
                low = mid + 1
            elif val < target:
                high = mid - 1
            else:
                return mid
        
        # 4. Target not found
        return -1

if __name__ == "__main__":
    solution = Task175()

    # Test Case 1
    ma1 = MountainArrayImpl([1, 2, 3, 4, 5, 3, 1])
    target1 = 3
    print(f"Test Case 1: {solution.findInMountainArray(target1, ma1)}") # Expected: 2

    # Test Case 2
    ma2 = MountainArrayImpl([0, 1, 2, 4, 2, 1])
    target2 = 3
    print(f"Test Case 2: {solution.findInMountainArray(target2, ma2)}") # Expected: -1

    # Test Case 3
    ma3 = MountainArrayImpl([1, 5, 2])
    target3 = 2
    print(f"Test Case 3: {solution.findInMountainArray(target3, ma3)}") # Expected: 2

    # Test Case 4
    ma4 = MountainArrayImpl([1, 2, 5, 4, 3])
    target4 = 5
    print(f"Test Case 4: {solution.findInMountainArray(target4, ma4)}") # Expected: 2

    # Test Case 5
    ma5 = MountainArrayImpl([3, 5, 3, 2, 0])
    target5 = 0
    print(f"Test Case 5: {solution.findInMountainArray(target5, ma5)}") # Expected: 4