
def remove_smallest(numbers):
    # Handle None or empty list
    if numbers is None or len(numbers) == 0:
        return []
    
    # Handle single element list
    if len(numbers) == 1:
        return []
    
    # Find the minimum value and its first index
    min_value = numbers[0]
    min_index = 0
    
    for i in range(1, len(numbers)):
        if numbers[i] < min_value:
            min_value = numbers[i]
            min_index = i
    
    # Create new list without mutating original
    result = []
    for i in range(len(numbers)):
        if i != min_index:
            result.append(numbers[i])
    
    return result


if __name__ == "__main__":
    # Test case 1
    test1 = [1, 2, 3, 4, 5]
    print(f"Test 1: {remove_smallest(test1)}")
    
    # Test case 2
    test2 = [5, 3, 2, 1, 4]
    print(f"Test 2: {remove_smallest(test2)}")
    
    # Test case 3
    test3 = [2, 2, 1, 2, 1]
    print(f"Test 3: {remove_smallest(test3)}")
    
    # Test case 4
    test4 = []
    print(f"Test 4: {remove_smallest(test4)}")
    
    # Test case 5
    test5 = [10]
    print(f"Test 5: {remove_smallest(test5)}")
