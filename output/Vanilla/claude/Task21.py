
def remove_smallest(numbers):
    if not numbers:
        return []
    
    result = numbers.copy()
    min_index = 0
    min_value = numbers[0]
    
    for i in range(1, len(numbers)):
        if numbers[i] < min_value:
            min_value = numbers[i]
            min_index = i
    
    result.pop(min_index)
    return result

if __name__ == "__main__":
    # Test case 1
    test1 = [1, 2, 3, 4, 5]
    print(f"Input: {test1}, Output: {remove_smallest(test1)}")
    
    # Test case 2
    test2 = [5, 3, 2, 1, 4]
    print(f"Input: {test2}, Output: {remove_smallest(test2)}")
    
    # Test case 3
    test3 = [2, 2, 1, 2, 1]
    print(f"Input: {test3}, Output: {remove_smallest(test3)}")
    
    # Test case 4
    test4 = []
    print(f"Input: {test4}, Output: {remove_smallest(test4)}")
    
    # Test case 5
    test5 = [10]
    print(f"Input: {test5}, Output: {remove_smallest(test5)}")
