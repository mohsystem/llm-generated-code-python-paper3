def posNegSort(arr):
    """
    Sorts the positive numbers in a list in ascending order,
    while keeping the negative numbers in their original positions.
    """
    # Handle empty list case gracefully.
    if not arr:
        return []

    # 1. Extract and sort the positive numbers.
    positives = sorted([n for n in arr if n > 0])
    
    # 2. Use an iterator for the sorted positive numbers.
    pos_iter = iter(positives)
    
    # 3. Reconstruct the list using a list comprehension.
    #    If the original number is positive, take the next value from the iterator.
    #    Otherwise, keep the original negative number.
    return [next(pos_iter) if n > 0 else n for n in arr]

def main():
    test_cases = [
        [6, 3, -2, 5, -8, 2, -2],
        [6, 5, 4, -1, 3, 2, -1, 1],
        [-5, -5, -5, -5, 7, -5],
        [],
        [5, -1, 4, -2, 3, -3, 2, -4, 1]
    ]

    for i, test_case in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        print(f"Original: {test_case}")
        result = posNegSort(test_case)
        print(f"Sorted:   {result}")
        print()

if __name__ == "__main__":
    main()