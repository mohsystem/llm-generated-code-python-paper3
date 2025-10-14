
from typing import List

def longest_run(arr: List[int]) -> int:
    if arr is None:
        raise ValueError("Array cannot be None")
    
    if not isinstance(arr, list):
        raise TypeError("Input must be a list")
    
    if len(arr) == 0:
        raise ValueError("Array cannot be empty")
    
    if len(arr) > 100000:
        raise ValueError("Array length exceeds maximum allowed size")
    
    for num in arr:
        if not isinstance(num, int):
            raise TypeError("All elements must be integers")
    
    if len(arr) == 1:
        return 1
    
    max_run = 1
    current_run = 1
    
    for i in range(1, len(arr)):
        diff = arr[i] - arr[i - 1]
        
        if diff == 1 or diff == -1:
            if i == 1 or (arr[i - 1] - arr[i - 2]) == diff:
                current_run += 1
            else:
                current_run = 2
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    
    return max_run

if __name__ == "__main__":
    print(f"Test 1: {longest_run([1, 2, 3, 5, 6, 7, 8, 9])}")
    print(f"Test 2: {longest_run([1, 2, 3, 10, 11, 15])}")
    print(f"Test 3: {longest_run([5, 4, 2, 1])}")
    print(f"Test 4: {longest_run([3, 5, 7, 10, 15])}")
    print(f"Test 5: {longest_run([10])}")
