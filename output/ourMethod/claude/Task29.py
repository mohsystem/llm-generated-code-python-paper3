
from typing import List, Tuple

def two_sum(numbers: List[int], target: int) -> Tuple[int, int]:
    if numbers is None or len(numbers) < 2:
        raise ValueError("Array must contain at least 2 elements")
    
    seen = {}
    
    for i in range(len(numbers)):
        complement = target - numbers[i]
        
        if complement in seen:
            return (seen[complement], i)
        
        seen[numbers[i]] = i
    
    raise ValueError("No valid pair found")


if __name__ == "__main__":
    result1 = two_sum([1, 2, 3], 4)
    print(result1)
    
    result2 = two_sum([3, 2, 4], 6)
    print(result2)
    
    result3 = two_sum([1, 5, 3, 7, 9], 12)
    print(result3)
    
    result4 = two_sum([10, 20, 30, 40], 50)
    print(result4)
    
    result5 = two_sum([-1, -2, -3, -4, -5], -8)
    print(result5)
