def filter_list(l):
    """
    Takes a list of non-negative integers and strings and
    returns a new list with the strings filtered out.
    """
    return [item for item in l if isinstance(item, int)]

if __name__ == '__main__':
    # Test Case 1
    list1 = [1, 2, 'a', 'b']
    print(f"Test Case 1 Input: {list1}")
    print(f"Filtered Output: {filter_list(list1)}\n")

    # Test Case 2
    list2 = [1, 'a', 'b', 0, 15]
    print(f"Test Case 2 Input: {list2}")
    print(f"Filtered Output: {filter_list(list2)}\n")

    # Test Case 3
    list3 = [1, 2, 'aasf', '1', '123', 123]
    print(f"Test Case 3 Input: {list3}")
    print(f"Filtered Output: {filter_list(list3)}\n")

    # Test Case 4
    list4 = ['hello', 'world', 2024]
    print(f"Test Case 4 Input: {list4}")
    print(f"Filtered Output: {filter_list(list4)}\n")

    # Test Case 5
    list5 = ['a', 'b', 'c']
    print(f"Test Case 5 Input: {list5}")
    print(f"Filtered Output: {filter_list(list5)}\n")