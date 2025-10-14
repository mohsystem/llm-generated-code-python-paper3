
def filter_list(lst):
    return [item for item in lst if isinstance(item, int) and not isinstance(item, bool)]

if __name__ == "__main__":
    # Test case 1
    print(filter_list([1, 2, "a", "b"]))
    
    # Test case 2
    print(filter_list([1, "a", "b", 0, 15]))
    
    # Test case 3
    print(filter_list([1, 2, "a", "b", "aasf", "1", "123", 123]))
    
    # Test case 4
    print(filter_list([10, 20, 30, "test", "hello", 40]))
    
    # Test case 5
    print(filter_list(["only", "strings", "here", "no", "numbers"]))
