
def get_value_at_index(args, index):
    if args is None or index < 0 or index >= len(args):
        return None
    return args[index]

if __name__ == "__main__":
    # Test case 1: Normal case with valid index
    test1 = ["arg0", "arg1", "arg2", "arg3"]
    print("Test 1:", get_value_at_index(test1, 1))
    
    # Test case 2: Index 0
    test2 = ["first", "second", "third"]
    print("Test 2:", get_value_at_index(test2, 0))
    
    # Test case 3: Last index
    test3 = ["a", "b", "c", "d", "e"]
    print("Test 3:", get_value_at_index(test3, 4))
    
    # Test case 4: Out of bounds index
    test4 = ["x", "y", "z"]
    print("Test 4:", get_value_at_index(test4, 5))
    
    # Test case 5: Negative index
    test5 = ["hello", "world"]
    print("Test 5:", get_value_at_index(test5, -1))
