
def remove_smallest(numbers):
    if not numbers:
        return []
    
    result = numbers.copy()
    
    # Find the index of the smallest value
    min_index = 0
    min_value = result[0]
    
    for i in range(1, len(result)):
        if result[i] < min_value:
            min_value = result[i]
            min_index = i
    
    # Remove the element at min_index
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
