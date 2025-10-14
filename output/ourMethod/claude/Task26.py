
from typing import List

def find_odd_occurrence(arr: List[int]) -> int:
    if arr is None:
        raise ValueError("Array cannot be None")
    if len(arr) == 0:
        raise ValueError("Array cannot be empty")
    if len(arr) > 1000000:
        raise ValueError("Array size exceeds maximum allowed")
    
    counts = {}
    
    for num in arr:
        if not isinstance(num, int):
            raise TypeError("Array must contain only integers")
        counts[num] = counts.get(num, 0) + 1
    
    for num, count in counts.items():
        if count % 2 != 0:
            return num
    
    raise ValueError("No number with odd occurrence found")

def main():
    test_cases = [
        [7],
        [0],
        [1, 1, 2],
        [0, 1, 0, 1, 0],
        [1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1]
    ]
    
    for i, test in enumerate(test_cases, 1):
        result = find_odd_occurrence(test)
        print(f"Test case {i}: {result}")

if __name__ == "__main__":
    main()
