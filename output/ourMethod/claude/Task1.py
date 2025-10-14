
from typing import List, Tuple

def count_passengers(bus_stops: List[Tuple[int, int]]) -> int:
    """\n    Calculate the number of people remaining on the bus after all stops.\n    \n    Args:\n        bus_stops: List of tuples (people_on, people_off) for each stop\n        \n    Returns:\n        Number of people still on the bus\n    """
    # Validate input is not None
    if bus_stops is None:
        raise ValueError("Input list cannot be None")
    
    people_on_bus = 0
    
    # Process each bus stop
    for i, stop in enumerate(bus_stops):
        # Validate stop is a tuple/list with exactly 2 elements
        if stop is None or len(stop) != 2:
            raise ValueError("Each bus stop must have exactly 2 values")
        
        get_on, get_off = stop
        
        # Validate types are integers
        if not isinstance(get_on, int) or not isinstance(get_off, int):
            raise ValueError("Number of people must be integers")
        
        # Validate non-negative values
        if get_on < 0 or get_off < 0:
            raise ValueError("Number of people cannot be negative")
        
        # Validate we don't have more people getting off than on the bus
        if get_off > people_on_bus:
            raise ValueError("Cannot have more people getting off than on bus")
        
        people_on_bus += get_on
        people_on_bus -= get_off
        
        # Ensure non-negative count
        if people_on_bus < 0:
            raise ValueError("People count cannot be negative")
    
    return people_on_bus

def main():
    # Test case 1: Basic case
    test1 = [(10, 0), (3, 5), (5, 8)]
    print(f"Test 1: {count_passengers(test1)}")  # Expected: 5
    
    # Test case 2: Multiple stops
    test2 = [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)]
    print(f"Test 2: {count_passengers(test2)}")  # Expected: 17
    
    # Test case 3: Single stop
    test3 = [(5, 0)]
    print(f"Test 3: {count_passengers(test3)}")  # Expected: 5
    
    # Test case 4: Multiple stops with zeros
    test4 = [(1, 0), (0, 0), (2, 1)]
    print(f"Test 4: {count_passengers(test4)}")  # Expected: 2
    
    # Test case 5: Larger numbers
    test5 = [(100, 0), (50, 25), (30, 55)]
    print(f"Test 5: {count_passengers(test5)}")  # Expected: 100

if __name__ == "__main__":
    main()
