def remove_smallest(numbers: list[int]) -> list[int]:
    """
    Given a list of integers, remove the smallest value.
    Do not mutate the original list.
    If there are multiple elements with the same value, remove the one with the lowest index.
    If you get an empty list, return an empty list.
    
    :param numbers: The input list of integers.
    :return: A new list with the smallest value removed.
    """
    if not numbers:
        return []

    # Create a copy to avoid mutating the original list
    new_list = numbers[:]
    
    # Find the index of the minimum value. list.index() finds the first occurrence.
    min_value = min(new_list)
    min_index = new_list.index(min_value)
    
    # Remove the element at that index
    new_list.pop(min_index)
    
    return new_list

# Alternative more Pythonic one-liner implementation
def remove_smallest_pythonic(numbers: list[int]) -> list[int]:
    if not numbers:
        return []
    min_index = numbers.index(min(numbers))
    # Slicing creates new lists, thus not mutating the original
    return numbers[:min_index] + numbers[min_index + 1:]

if __name__ == '__main__':
    # Test Cases
    test_cases = [
        [1, 2, 3, 4, 5],
        [5, 3, 2, 1, 4],
        [2, 2, 1, 2, 1],
        [],
        [3, 3, 3, 3, 3]
    ]

    for i, original in enumerate(test_cases):
        # We use the pythonic version for the output
        result = remove_smallest_pythonic(original)
        print(f"Test Case {i + 1}:")
        print(f"Original: {original}")
        print(f"Result:   {result}")
        print()