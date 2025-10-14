
def count_passengers(bus_stops):
    # Input validation
    if bus_stops is None or not isinstance(bus_stops, list):
        return 0
    
    people_on_bus = 0
    
    # Process each bus stop
    for stop in bus_stops:
        # Validate structure
        if not isinstance(stop, (list, tuple)) or len(stop) != 2:
            continue
        
        # Validate non-negative values
        if not isinstance(stop[0], int) or not isinstance(stop[1], int):
            continue
        
        if stop[0] < 0 or stop[1] < 0:
            continue
        
        # Add people getting on, subtract people getting off
        people_on_bus += stop[0]
        people_on_bus -= stop[1]
        
        # Ensure non-negative passenger count
        if people_on_bus < 0:
            people_on_bus = 0
    
    return people_on_bus


if __name__ == "__main__":
    # Test case 1: Simple case
    test1 = [[10, 0], [3, 5], [5, 8]]
    print(f"Test 1: {count_passengers(test1)}")  # Expected: 5
    
    # Test case 2: Multiple stops
    test2 = [[3, 0], [9, 1], [4, 10], [12, 2], [6, 1], [7, 10]]
    print(f"Test 2: {count_passengers(test2)}")  # Expected: 17
    
    # Test case 3: Empty bus at end
    test3 = [[5, 0], [2, 3], [0, 4]]
    print(f"Test 3: {count_passengers(test3)}")  # Expected: 0
    
    # Test case 4: Single stop
    test4 = [[10, 0]]
    print(f"Test 4: {count_passengers(test4)}")  # Expected: 10
    
    # Test case 5: Multiple stops
    test5 = [[3, 0], [2, 1], [5, 3], [1, 4]]
    print(f"Test 5: {count_passengers(test5)}")  # Expected: 3
