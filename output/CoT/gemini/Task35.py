def count_passengers(stops):
    """
    Calculates the number of people on the bus after the last stop.
    """
    return sum(on_bus - off_bus for on_bus, off_bus in stops)

# main method with test cases
if __name__ == '__main__':
    # Test Case 1
    test1 = [[10, 0], [3, 5], [5, 8]]
    print(f"Remaining passengers: {count_passengers(test1)}") # Expected: 5

    # Test Case 2
    test2 = [[3, 0], [9, 1], [4, 10], [12, 2], [6, 1], [7, 10]]
    print(f"Remaining passengers: {count_passengers(test2)}") # Expected: 17

    # Test Case 3
    test3 = [[3, 0], [9, 1], [4, 8], [12, 2], [6, 1], [7, 8]]
    print(f"Remaining passengers: {count_passengers(test3)}") # Expected: 21

    # Test Case 4
    test4 = [[0, 0]]
    print(f"Remaining passengers: {count_passengers(test4)}") # Expected: 0
    
    # Test Case 5
    test5 = [[100, 0], [20, 30], [5, 15]]
    print(f"Remaining passengers: {count_passengers(test5)}") # Expected: 80