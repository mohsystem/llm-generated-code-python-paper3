from typing import List

def count_passengers(stops: List[List[int]]) -> int:
    """
    Calculates the number of people still on the bus after the last bus stop.

    Args:
        stops: A list of integer pairs. Each pair represents [people get on, people get off].
    
    Returns:
        The number of people left on the bus.
    """
    return sum(on - off for on, off in stops)

if __name__ == '__main__':
    # Test Case 1
    stops1 = [[10, 0], [3, 5], [5, 8]]
    print(f"Test Case 1: {stops1}")
    print(f"Remaining passengers: {count_passengers(stops1)}") # Expected: 5

    # Test Case 2
    stops2 = [[3, 0], [9, 1], [4, 10], [12, 2], [6, 1], [7, 10]]
    print(f"\nTest Case 2: {stops2}")
    print(f"Remaining passengers: {count_passengers(stops2)}") # Expected: 17

    # Test Case 3
    stops3 = [[3, 0], [9, 1], [4, 8], [12, 2], [6, 1], [7, 8]]
    print(f"\nTest Case 3: {stops3}")
    print(f"Remaining passengers: {count_passengers(stops3)}") # Expected: 21

    # Test Case 4
    stops4 = [[0, 0]]
    print(f"\nTest Case 4: {stops4}")
    print(f"Remaining passengers: {count_passengers(stops4)}") # Expected: 0

    # Test Case 5
    stops5 = [[100, 0], [0, 50], [20, 30]]
    print(f"\nTest Case 5: {stops5}")
    print(f"Remaining passengers: {count_passengers(stops5)}") # Expected: 40