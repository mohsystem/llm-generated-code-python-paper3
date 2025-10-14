
def create_phone_number(numbers):
    # Input validation
    if numbers is None:
        raise ValueError("Input array cannot be None")
    
    if len(numbers) != 10:
        raise ValueError("Array must contain exactly 10 elements")
    
    # Validate each element is between 0-9
    for i in range(len(numbers)):
        if not isinstance(numbers[i], int) or numbers[i] < 0 or numbers[i] > 9:
            raise ValueError("All elements must be integers between 0 and 9")
    
    # Build phone number using secure string formatting
    phone_number = "({}{}{}) {}{}{}-{}{}{}{}".format(
        numbers[0], numbers[1], numbers[2],
        numbers[3], numbers[4], numbers[5],
        numbers[6], numbers[7], numbers[8], numbers[9]
    )
    
    return phone_number


if __name__ == "__main__":
    # Test case 1: Standard input
    test1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    print("Test 1:", create_phone_number(test1))
    
    # Test case 2: All zeros
    test2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    print("Test 2:", create_phone_number(test2))
    
    # Test case 3: All nines
    test3 = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9]
    print("Test 3:", create_phone_number(test3))
    
    # Test case 4: Mixed numbers
    test4 = [5, 5, 5, 1, 2, 3, 4, 5, 6, 7]
    print("Test 4:", create_phone_number(test4))
    
    # Test case 5: Another mixed pattern
    test5 = [8, 0, 0, 5, 5, 5, 1, 2, 3, 4]
    print("Test 5:", create_phone_number(test5))
