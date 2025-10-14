
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
    print("Test 1:", two_sum([1, 2, 3], 4))
    
    # Test case 2
    print("Test 2:", two_sum([3, 2, 4], 6))
    
    # Test case 3
    print("Test 3:", two_sum([1, 5, 3, 7, 9], 12))
    
    # Test case 4
    print("Test 4:", two_sum([10, 20, 30, 40], 50))
    
    # Test case 5
    print("Test 5:", two_sum([-1, -2, -3, -4], -6))
