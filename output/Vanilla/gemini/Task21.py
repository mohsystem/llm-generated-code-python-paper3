def remove_smallest(numbers):
    """
    Given a list of integers, remove the smallest value.
    Do not mutate the original list.
    If there are multiple elements with the same value, remove the one with the lowest index.
    If you get an empty list, return an empty list.
    """
    if not numbers:
        return []
    
    # Create a copy to not mutate the original list
    new_list = list(numbers)
    
    # min() finds the smallest value, and remove() removes the first occurrence
    new_list.remove(min(new_list))
    
    return new_list

if __name__ == '__main__':
    test_cases = [
        [1, 2, 3, 4, 5],
        [5, 3, 2, 1, 4],
        [2, 2, 1, 2, 1],
        [10],
        []
    ]

    for case in test_cases:
        print(f"Input:  {case}")
        original_copy = list(case) # To check for mutation
        result = remove_smallest(case)
        print(f"Output: {result}")
        print(f"Original untouched: {case == original_copy}")
        print("---")