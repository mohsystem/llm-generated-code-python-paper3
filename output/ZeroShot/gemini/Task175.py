# This is the MountainArray's API interface.
# You should not implement it, or speculate about its implementation
class MountainArray:
   def get(self, index: int) -> int:
       pass
   def length(self) -> int:
       pass

# Dummy implementation for testing purposes
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

        # 1. Find the peak index
        low, high = 0, length - 1
        peak_index = -1
        while low < high:
            mid = low + (high - low) // 2
            if mountain_arr.get(mid) < mountain_arr.get(mid + 1):
                low = mid + 1
            else:
                high = mid
        peak_index = low

        # 2. Search in the ascending part [0, peak_index]
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

        # 3. Search in the descending part [peak_index + 1, length - 1]
        low, high = peak_index + 1, length - 1
        while low <= high:
            mid = low + (high - low) // 2
            val = mountain_arr.get(mid)
            if val == target:
                return mid
            elif val < target: # descending
                high = mid - 1
            else:
                low = mid + 1

        return -1


if __name__ == '__main__':
    solution = Task175()

    # Test Case 1
    mountain_arr1 = MountainArrayImpl([1, 2, 3, 4, 5, 3, 1])
    target1 = 3
    print(f"Test Case 1: {solution.findInMountainArray(target1, mountain_arr1)}")

    # Test Case 2
    mountain_arr2 = MountainArrayImpl([0, 1, 2, 4, 2, 1])
    target2 = 3
    print(f"Test Case 2: {solution.findInMountainArray(target2, mountain_arr2)}")

    # Test Case 3
    mountain_arr3 = MountainArrayImpl([1, 5, 2])
    target3 = 2
    print(f"Test Case 3: {solution.findInMountainArray(target3, mountain_arr3)}")

    # Test Case 4
    mountain_arr4 = MountainArrayImpl([1, 2, 5, 2, 1])
    target4 = 1
    print(f"Test Case 4: {solution.findInMountainArray(target4, mountain_arr4)}")
    
    # Test Case 5
    mountain_arr5 = MountainArrayImpl([1, 2, 5, 2, 1])
    target5 = 5
    print(f"Test Case 5: {solution.findInMountainArray(target5, mountain_arr5)}")