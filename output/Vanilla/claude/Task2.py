
def create_phone_number(numbers):
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
    test3 = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9]
    print(create_phone_number(test3))
    
    # Test case 4
    test4 = [5, 5, 5, 1, 2, 3, 4, 5, 6, 7]
    print(create_phone_number(test4))
    
    # Test case 5
    test5 = [8, 6, 7, 5, 3, 0, 9, 1, 2, 3]
    print(create_phone_number(test5))
