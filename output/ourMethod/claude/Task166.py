
from typing import List

def pos_neg_sort(arr: List[int]) -> List[int]:
    if arr is None:
        return []
    
    # Create a copy to avoid modifying the input
    result = arr.copy()
    
    # Extract positive numbers and sort them
    positives = sorted([num for num in result if num > 0])
    
    # Replace positive numbers in result with sorted ones
    pos_index = 0
    for i in range(len(result)):
        if result[i] > 0:
            result[i] = positives[pos_index]
            pos_index += 1
    
    return result

if __name__ == "__main__":
    # Test case 1
    print(pos_neg_sort([6, 3, -2, 5, -8, 2, -2]))
    
    # Test case 2
    print(pos_neg_sort([6, 5, 4, -1, 3, 2, -1, 1]))
    
    # Test case 3
    print(pos_neg_sort([-5, -5, -5, -5, 7, -5]))
    
    # Test case 4
    print(pos_neg_sort([]))
    
    # Test case 5
    print(pos_neg_sort([-1, -2, -3]))
