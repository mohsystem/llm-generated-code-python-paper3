def posNegSort(arr):
    """
    Sorts the positive numbers in a list in ascending order,
    while keeping the negative numbers in their original positions.
    """
    # 1. Extract and sort positive numbers
    positives = sorted([num for num in arr if num > 0])
    
    # An iterator for the sorted positive numbers
    pos_iter = iter(positives)
    
    # 2. Build the result list, replacing positives with their sorted counterparts
    result = [next(pos_iter) if num > 0 else num for num in arr]
    
    return result

# main method with 5 test cases
if __name__ == '__main__':
    test_cases = [
        [6, 3, -2, 5, -8, 2, -2],
        [6, 5, 4, -1, 3, 2, -1, 1],
        [-5, -5, -5, -5, 7, -5],
        [],
        [5, 4, 3, 2, 1]
    ]

    for test_case in test_cases:
        print(f"Original: {test_case}")
        result = posNegSort(test_case)
        print(f"Sorted:   {result}")
        print()