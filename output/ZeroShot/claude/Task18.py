
def binary_array_to_number(binary):
    if not binary:
        return 0
    
    result = 0
    for bit in binary:
        result = result * 2 + bit
    return result


if __name__ == "__main__":
    # Test case 1
    test1 = [0, 0, 0, 1]
    print(f"Testing: [0, 0, 0, 1] ==> {binary_array_to_number(test1)}")
    
    # Test case 2
    test2 = [0, 0, 1, 0]
    print(f"Testing: [0, 0, 1, 0] ==> {binary_array_to_number(test2)}")
    
    # Test case 3
    test3 = [0, 1, 0, 1]
    print(f"Testing: [0, 1, 0, 1] ==> {binary_array_to_number(test3)}")
    
    # Test case 4
    test4 = [1, 0, 0, 1]
    print(f"Testing: [1, 0, 0, 1] ==> {binary_array_to_number(test4)}")
    
    # Test case 5
    test5 = [1, 1, 1, 1]
    print(f"Testing: [1, 1, 1, 1] ==> {binary_array_to_number(test5)}")
