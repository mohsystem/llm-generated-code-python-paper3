
def two_sum(numbers, target):
    if not numbers or len(numbers) < 2:
        return []
    
    seen = {}
    
    for i, num in enumerate(numbers):
        complement = target - num
        
        if complement in seen:
            return [seen[complement], i]
        
        seen[num] = i
    
    return []

if __name__ == "__main__":
    # Test case 1
    result1 = two_sum([1, 2, 3], 4)
    print(f"Test 1: {result1}")
    
    # Test case 2
    result2 = two_sum([3, 2, 4], 6)
    print(f"Test 2: {result2}")
    
    # Test case 3
    result3 = two_sum([1, 5, 3, 7, 9], 10)
    print(f"Test 3: {result3}")
    
    # Test case 4
    result4 = two_sum([10, 20, 30, 40], 70)
    print(f"Test 4: {result4}")
    
    # Test case 5
    result5 = two_sum([-1, -2, -3, -4, -5], -8)
    print(f"Test 5: {result5}")
