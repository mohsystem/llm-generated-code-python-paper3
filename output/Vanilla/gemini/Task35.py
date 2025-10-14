def count_passengers(stops):
    """
    Calculates the number of people still on the bus after the last bus stop.
    :param stops: A list of integer pairs. Each pair represents [people_on, people_off].
    :return: The number of people remaining on the bus.
    """
    return sum(on - off for on, off in stops)

if __name__ == '__main__':
    # Test Case 1
    test1 = [[10, 0], [3, 5], [5, 8]]
    print(f"Test 1: {count_passengers(test1)}") # Expected: 5

    # Test Case 2
    test2 = [[3, 0], [9, 1], [4, 10], [12, 2], [6, 1], [7, 10]]
    print(f"Test 2: {count_passengers(test2)}") # Expected: 17

    # Test Case 3
    test3 = [[3, 0], [9, 1], [4, 8], [12, 2], [6, 1], [7, 8]]
    print(f"Test 3: {count_passengers(test3)}") # Expected: 21
    
    # Test Case 4
    test4 = [[0, 0]]
    print(f"Test 4: {count_passengers(test4)}") # Expected: 0
    
    # Test Case 5
    test5 = [[10, 0], [1, 1], [2, 2], [3, 3], [4, 10]]
    print(f"Test 5: {count_passengers(test5)}") # Expected: 4