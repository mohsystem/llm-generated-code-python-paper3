
def find_odd(array):
    count_dict = {}
    
    for num in array:
        count_dict[num] = count_dict.get(num, 0) + 1
    
    for num, count in count_dict.items():
        if count % 2 != 0:
            return num
    
    return 0

if __name__ == "__main__":
    # Test case 1
    test1 = [7]
    print(f"Test 1: {find_odd(test1)}")  # Expected: 7
    
    # Test case 2
    test2 = [0]
    print(f"Test 2: {find_odd(test2)}")  # Expected: 0
    
    # Test case 3
    test3 = [1, 1, 2]
    print(f"Test 3: {find_odd(test3)}")  # Expected: 2
    
    # Test case 4
    test4 = [0, 1, 0, 1, 0]
    print(f"Test 4: {find_odd(test4)}")  # Expected: 0
    
    # Test case 5
    test5 = [1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1]
    print(f"Test 5: {find_odd(test5)}")  # Expected: 4
