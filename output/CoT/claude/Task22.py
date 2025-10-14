
def filter_list(lst):
    if lst is None:
        return []
    
    result = []
    for item in lst:
        if isinstance(item, int) and not isinstance(item, bool):
            result.append(item)
    return result


if __name__ == "__main__":
    # Test case 1
    print(filter_list([1, 2, "a", "b"]))
    
    # Test case 2
    print(filter_list([1, "a", "b", 0, 15]))
    
    # Test case 3
    print(filter_list([1, 2, "a", "b", "aasf", "1", "123", 123]))
    
    # Test case 4
    print(filter_list([]))
    
    # Test case 5
    print(filter_list([100, 200, "test", 300]))
