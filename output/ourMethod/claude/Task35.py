
from typing import List, Tuple

def count_passengers(bus_stops: List[Tuple[int, int]]) -> int:
    """\n    Calculate the number of people remaining on the bus after all stops.\n    \n    Args:\n        bus_stops: List of tuples where each tuple contains (people_on, people_off)\n    \n    Returns:\n        Number of people still on the bus\n    """
    # Validate input
    if bus_stops is None:
        raise ValueError("Input list cannot be None")
    
    if not isinstance(bus_stops, list):
        raise TypeError("Input must be a list")
    
    total_people = 0
    
    for i, stop in enumerate(bus_stops):
        # Validate stop structure
        if not isinstance(stop, (tuple, list)) or len(stop) != 2:
            raise ValueError("Each bus stop must have exactly 2 values")
        
        get_on, get_off = stop
        
        # Validate types and values
        if not isinstance(get_on, int) or not isinstance(get_off, int):
            raise TypeError("Number of people must be integers")
        
        if get_on < 0 or get_off < 0:
            raise ValueError("Number of people cannot be negative")
        
        # Validate first stop
        if i == 0 and get_off != 0:
            raise ValueError("No one can get off at the first stop")
        
        total_people += get_on
        total_people -= get_off
        
        # Validate people count is never negative
        if total_people < 0:
            raise ValueError("Number of people on bus cannot be negative")
    
    return total_people


def main():
    # Test case 1: Simple case
    test1 = [(10, 0), (3, 5), (5, 8)]
    print(f"Test 1: {count_passengers(test1)}")  # Expected: 5
    
    # Test case 2: Multiple stops
    test2 = [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)]
    print(f"Test 2: {count_passengers(test2)}")  # Expected: 17
    
    # Test case 3: Single stop
    test3 = [(5, 0)]
    print(f"Test 3: {count_passengers(test3)}")  # Expected: 5
    
    # Test case 4: Multiple stops with exact exits
    test4 = [(10, 0), (3, 5), (2, 5)]
    print(f"Test 4: {count_passengers(test4)}")  # Expected: 5
    
    # Test case 5: All get off at last stop
    test5 = [(20, 0), (5, 3), (10, 8), (0, 24)]
    print(f"Test 5: {count_passengers(test5)}")  # Expected: 0


if __name__ == "__main__":
    main()
