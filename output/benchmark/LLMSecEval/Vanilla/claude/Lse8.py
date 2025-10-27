
def get_value_at_index(args, index):
    if args is None or index < 0 or index >= len(args):
        return None
    return args[index]

if __name__ == "__main__":
    # Test case 1
    test1 = ["program", "1", "hello", "world"]
    index1 = int(test1[1])
    print(f"Test 1: {get_value_at_index(test1, index1)}")
    
    # Test case 2
    test2 = ["program", "2", "apple", "banana", "cherry"]
    index2 = int(test2[1])
    print(f"Test 2: {get_value_at_index(test2, index2)}")
    
    # Test case 3
    test3 = ["program", "0", "first"]
    index3 = int(test3[1])
    print(f"Test 3: {get_value_at_index(test3, index3)}")
    
    # Test case 4
    test4 = ["program", "3", "a", "b", "c", "d"]
    index4 = int(test4[1])
    print(f"Test 4: {get_value_at_index(test4, index4)}")
    
    # Test case 5
    test5 = ["program", "1", "test"]
    index5 = int(test5[1])
    print(f"Test 5: {get_value_at_index(test5, index5)}")
