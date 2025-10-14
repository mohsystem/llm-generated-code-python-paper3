
# MountainArray interface (provided by the problem)
class MountainArray:
    def get(self, index: int) -> int:
        pass
    
    def length(self) -> int:
        pass

class Task175:
    def findInMountainArray(self, target: int, mountain_arr: 'MountainArray') -> int:
        # Input validation
        if mountain_arr is None:
            return -1
        
        length = mountain_arr.length()
        if length < 3:
            return -1
        
        # Step 1: Find the peak index
        peak_index = self.find_peak(mountain_arr, length)
        
        # Step 2: Search in the ascending part (left side)
        result = self.binary_search_ascending(mountain_arr, target, 0, peak_index)
        
        # Step 3: If not found, search in the descending part (right side)
        if result == -1:
            result = self.binary_search_descending(mountain_arr, target, peak_index + 1, length - 1)
        
        return result
    
    def find_peak(self, mountain_arr: 'MountainArray', length: int) -> int:
        left, right = 0, length - 1
        
        while left < right:
            mid = left + (right - left) // 2
            mid_val = mountain_arr.get(mid)
            next_val = mountain_arr.get(mid + 1)
            
            if mid_val < next_val:
                left = mid + 1
            else:
                right = mid
        
        return left
    
    def binary_search_ascending(self, mountain_arr: 'MountainArray', target: int, left: int, right: int) -> int:
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
    
    def binary_search_descending(self, mountain_arr: 'MountainArray', target: int, left: int, right: int) -> int:
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

# Test implementation of MountainArray
class TestMountainArray(MountainArray):
    def __init__(self, arr):
        self.arr = arr
    
    def get(self, index: int) -> int:
        return self.arr[index]
    
    def length(self) -> int:
        return len(self.arr)

if __name__ == "__main__":
    solution = Task175()
    
    # Test case 1
    test1 = TestMountainArray([1, 2, 3, 4, 5, 3, 1])
    print(f"Test 1: {solution.findInMountainArray(3, test1)}")  # Expected: 2
    
    # Test case 2
    test2 = TestMountainArray([0, 1, 2, 4, 2, 1])
    print(f"Test 2: {solution.findInMountainArray(3, test2)}")  # Expected: -1
    
    # Test case 3
    test3 = TestMountainArray([1, 2, 3, 4, 5, 3, 1])
    print(f"Test 3: {solution.findInMountainArray(5, test3)}")  # Expected: 4
    
    # Test case 4
    test4 = TestMountainArray([0, 5, 3, 1])
    print(f"Test 4: {solution.findInMountainArray(1, test4)}")  # Expected: 3
    
    # Test case 5
    test5 = TestMountainArray([1, 5, 2])
    print(f"Test 5: {solution.findInMountainArray(2, test5)}")  # Expected: 2
