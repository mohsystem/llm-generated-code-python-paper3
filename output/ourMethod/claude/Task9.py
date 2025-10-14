
from typing import List

def odd_or_even(array: List[int]) -> str:
    if array is None:
        raise ValueError("Input array cannot be None")
    
    if not isinstance(array, list):
        raise TypeError("Input must be a list")
    
    if not array:
        return "even"
    
    for num in array:
        if not isinstance(num, int) or isinstance(num, bool):
            raise TypeError("All array elements must be integers")
    
    total = sum(array)
    return "even" if total % 2 == 0 else "odd"

if __name__ == "__main__":
    print(odd_or_even([0]))
    print(odd_or_even([0, 1, 4]))
    print(odd_or_even([0, -1, -5]))
    print(odd_or_even([]))
    print(odd_or_even([1, 2, 3, 4, 5]))
