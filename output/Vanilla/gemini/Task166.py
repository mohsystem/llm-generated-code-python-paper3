def posNegSort(arr):
    """
    Sorts the positive numbers in a list in ascending order,
    while keeping the negative numbers in their original positions.
    """
    # 1. Extract and sort positive numbers
    positives = sorted([num for num in arr if num > 0])
    
    # 2. Create an iterator for the sorted positive numbers
    pos_iter = iter(positives)
    
    # 3. Build the result list by replacing positives with sorted ones
    return [next(pos_iter) if num > 0 else num for num in arr]

if __name__ == '__main__':
    # Test Case 1
    arr1 = [6, 3, -2, 5, -8, 2, -2]
    print(f"Test 1 Input: {arr1}")
    print(f"Test 1 Output: {posNegSort(arr1)}")

    # Test Case 2
    arr2 = [6, 5, 4, -1, 3, 2, -1, 1]
    print(f"Test 2 Input: {arr2}")
    print(f"Test 2 Output: {posNegSort(arr2)}")

    # Test Case 3
    arr3 = [-5, -5, -5, -5, 7, -5]
    print(f"Test 3 Input: {arr3}")
    print(f"Test 3 Output: {posNegSort(arr3)}")

    # Test Case 4
    arr4 = []
    print(f"Test 4 Input: {arr4}")
    print(f"Test 4 Output: {posNegSort(arr4)}")

    # Test Case 5
    arr5 = [-1, -2, -3, 1, 2, 3]
    print(f"Test 5 Input: {arr5}")
    print(f"Test 5 Output: {posNegSort(arr5)}")