
def create_phone_number(numbers):
    if numbers is None or len(numbers) != 10:
        raise ValueError("Array must contain exactly 10 integers")
    
    for num in numbers:
        if not isinstance(num, int) or num < 0 or num > 9:
            raise ValueError("All numbers must be integers between 0 and 9")
    
    return "({}{}{}) {}{}{}-{}{}{}{}".format(
        numbers[0], numbers[1], numbers[2],
        numbers[3], numbers[4], numbers[5],
        numbers[6], numbers[7], numbers[8], numbers[9]
    )

if __name__ == "__main__":
    # Test case 1
    test1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    print(create_phone_number(test1))
    
    # Test case 2
    test2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    print(create_phone_number(test2))
    
    # Test case 3
    test3 = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    print(create_phone_number(test3))
    
    # Test case 4
    test4 = [5, 5, 5, 1, 2, 3, 4, 5, 6, 7]
    print(create_phone_number(test4))
    
    # Test case 5
    test5 = [1, 1, 1, 2, 2, 2, 3, 3, 3, 4]
    print(create_phone_number(test5))
