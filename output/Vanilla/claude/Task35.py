
def count_passengers(bus_stops):
    people_on_bus = 0
    
    for stop in bus_stops:
        people_on_bus += stop[0]  # people getting on
        people_on_bus -= stop[1]  # people getting off
    
    return people_on_bus


if __name__ == "__main__":
    # Test case 1
    test1 = [[10, 0], [3, 5], [5, 8]]
    print(f"Test 1: {count_passengers(test1)}")  # Expected: 5
    
    # Test case 2
    test2 = [[3, 0], [9, 1], [4, 10], [12, 2], [6, 1], [7, 10]]
    print(f"Test 2: {count_passengers(test2)}")  # Expected: 17
    
    # Test case 3
    test3 = [[3, 0], [9, 1], [4, 8], [12, 2], [6, 1], [7, 8]]
    print(f"Test 3: {count_passengers(test3)}")  # Expected: 21
    
    # Test case 4
    test4 = [[0, 0]]
    print(f"Test 4: {count_passengers(test4)}")  # Expected: 0
    
    # Test case 5
    test5 = [[5, 0], [2, 3], [1, 1], [4, 2]]
    print(f"Test 5: {count_passengers(test5)}")  # Expected: 6
