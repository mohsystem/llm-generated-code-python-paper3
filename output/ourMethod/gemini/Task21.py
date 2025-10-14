from typing import List

def remove_smallest(numbers: List[int]) -> List[int]:
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
    
    # Find the index of the first occurrence of the minimum value
    min_index = new_list.index(min(new_list))
    
    # Remove the element at that index
    new_list.pop(min_index)
    
    return new_list

if __name__ == '__main__':
    # Test cases
    test_cases = [
        [1, 2, 3, 4, 5],
        [5, 3, 2, 1, 4],
        [2, 2, 1, 2, 1],
        [42],
        []
    ]

    for i, original in enumerate(test_cases):
        print(f"Test Case #{i + 1}")
        print(f"Original: {original}")
        result = remove_smallest(original)
        print(f"Result:   {result}")
        print(f"Original after call: {original}") # Verify original is not mutated
        print()