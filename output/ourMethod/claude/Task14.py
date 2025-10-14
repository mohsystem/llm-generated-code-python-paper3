
from typing import List, Optional

def find_equal_index(arr: Optional[List[int]]) -> int:
    # Validate input
    if arr is None or len(arr) == 0 or len(arr) >= 1000:
        return -1
    
    # Validate that all elements are integers
    if not all(isinstance(x, int) for x in arr):
        return -1
    
    # Calculate total sum
    total_sum = sum(arr)
    
    # Iterate through array to find equilibrium index
    left_sum = 0
    for i in range(len(arr)):
        # Right sum = total - left - current element
        right_sum = total_sum - left_sum - arr[i]
        
        if left_sum == right_sum:
            return i
        
        left_sum += arr[i]
    
    return -1

def main():
    # Test case 1
    test1 = [1, 2, 3, 4, 3, 2, 1]
    print(f"Test 1: {find_equal_index(test1)} (expected: 3)")
    
    # Test case 2
    test2 = [1, 100, 50, -51, 1, 1]
    print(f"Test 2: {find_equal_index(test2)} (expected: 1)")
    
    # Test case 3
    test3 = [20, 10, -80, 10, 10, 15, 35]
    print(f"Test 3: {find_equal_index(test3)} (expected: 0)")
    
    # Test case 4
    test4 = [1, 2, 3]
    print(f"Test 4: {find_equal_index(test4)} (expected: -1)")
    
    # Test case 5
    test5 = [0, 0, 0, 0]
    print(f"Test 5: {find_equal_index(test5)} (expected: 0)")

if __name__ == "__main__":
    main()
