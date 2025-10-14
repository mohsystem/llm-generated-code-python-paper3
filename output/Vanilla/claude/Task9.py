
def odd_or_even(array):
    if not array:
        return "even"
    
    total = sum(array)
    return "even" if total % 2 == 0 else "odd"


if __name__ == "__main__":
    # Test case 1
    test1 = [0]
    print(f"Test 1: {odd_or_even(test1)}")  # Expected: "even"
    
    # Test case 2
    test2 = [0, 1, 4]
    print(f"Test 2: {odd_or_even(test2)}")  # Expected: "odd"
    
    # Test case 3
    test3 = [0, -1, -5]
    print(f"Test 3: {odd_or_even(test3)}")  # Expected: "even"
    
    # Test case 4
    test4 = []
    print(f"Test 4: {odd_or_even(test4)}")  # Expected: "even"
    
    # Test case 5
    test5 = [1, 2, 3, 4, 5]
    print(f"Test 5: {odd_or_even(test5)}")  # Expected: "odd"
