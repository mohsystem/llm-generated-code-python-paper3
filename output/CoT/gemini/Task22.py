def filter_list(l):
    """
    Filters a list of non-negative integers and strings,
    returning a new list with only the integers.

    :param l: The input list containing non-negative integers and strings.
    :return: A new list containing only the integers.
    """
    # List comprehension provides a concise and safe way to build the new list.
    # isinstance(item, int) checks if the item's type is an integer.
    # It safely handles different data types without causing errors.
    return [item for item in l if isinstance(item, int)]

if __name__ == '__main__':
    # Test Case 1
    list1 = [1, 2, 'a', 'b']
    print(f"Test Case 1: {list1}")
    print(f"Filtered: {filter_list(list1)}") # Expected: [1, 2]
    print()

    # Test Case 2
    list2 = [1, 'a', 'b', 0, 15]
    print(f"Test Case 2: {list2}")
    print(f"Filtered: {filter_list(list2)}") # Expected: [1, 0, 15]
    print()

    # Test Case 3
    list3 = [1, 2, 'aasf', '1', '123', 123]
    print(f"Test Case 3: {list3}")
    print(f"Filtered: {filter_list(list3)}") # Expected: [1, 2, 123]
    print()

    # Test Case 4: All strings
    list4 = ['hello', 'world', '123']
    print(f"Test Case 4: {list4}")
    print(f"Filtered: {filter_list(list4)}") # Expected: []
    print()

    # Test Case 5: Empty list
    list5 = []
    print(f"Test Case 5: {list5}")
    print(f"Filtered: {filter_list(list5)}") # Expected: []
    print()