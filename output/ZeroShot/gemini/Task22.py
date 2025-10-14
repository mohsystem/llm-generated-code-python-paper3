def filter_list(l):
    """
    Filters a list, returning a new list containing only non-negative integers.

    :param l: The input list containing non-negative integers and strings.
    :return: A new list with strings filtered out.
    """
    if not isinstance(l, list):
        return []
    return [item for item in l if isinstance(item, int) and item >= 0]

if __name__ == '__main__':
    # Test Case 1
    list1 = [1, 2, 'a', 'b']
    print(f"Test 1 Input: {list1}")
    print(f"Test 1 Output: {filter_list(list1)}") # Expected: [1, 2]

    # Test Case 2
    list2 = [1, 'a', 'b', 0, 15]
    print(f"Test 2 Input: {list2}")
    print(f"Test 2 Output: {filter_list(list2)}") # Expected: [1, 0, 15]

    # Test Case 3
    list3 = [1, 2, 'aasf', '1', '123', 123]
    print(f"Test 3 Input: {list3}")
    print(f"Test 3 Output: {filter_list(list3)}") # Expected: [1, 2, 123]

    # Test Case 4: With negative numbers
    list4 = [-1, 'c', 5, -9, 'd']
    print(f"Test 4 Input: {list4}")
    print(f"Test 4 Output: {filter_list(list4)}") # Expected: [5]

    # Test Case 5: Empty list
    list5 = []
    print(f"Test 5 Input: {list5}")
    print(f"Test 5 Output: {filter_list(list5)}") # Expected: []