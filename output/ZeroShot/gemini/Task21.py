def remove_smallest(numbers):
    """
    Given a list of integers, removes the smallest value.
    This function does not mutate the original list.

    :param numbers: The input list of integers.
    :return: A new list with the first occurrence of the smallest value removed.
             Returns an empty list if the input is empty.
    """
    if not numbers:
        return []
    
    # Create a copy to avoid mutating the original list.
    result = list(numbers)
    
    # list.remove() removes the first occurrence of a value.
    result.remove(min(result))
    
    return result

if __name__ == '__main__':
    test_cases = [
        [1, 2, 3, 4, 5],
        [5, 3, 2, 1, 4],
        [2, 2, 1, 2, 1],
        [1],
        []
    ]

    for test_case in test_cases:
        result = remove_smallest(test_case)
        print(result)