from typing import List

def count_passengers(stops: List[List[int]]) -> int:
    """
    Calculates the number of people still on the bus after the last bus stop.

    :param stops: A list of integer pairs. Each pair represents [people_on, people_off].
    :return: The number of people remaining on the bus.
    """
    people_on_bus = 0
    for on, off in stops:
        people_on_bus += on
        people_on_bus -= off
    return people_on_bus

if __name__ == '__main__':
    # Test Case 1
    test1 = [[10, 0], [3, 5], [5, 8]]
    print(f"Test Case 1: {count_passengers(test1)}") # Expected: 5

    # Test Case 2
    test2 = [[3, 0], [9, 1], [4, 10], [12, 2], [6, 1], [7, 10]]
    print(f"Test Case 2: {count_passengers(test2)}") # Expected: 17

    # Test Case 3
    test3 = [[3, 0], [9, 1], [4, 8], [12, 2], [6, 1], [7, 8]]
    print(f"Test Case 3: {count_passengers(test3)}") # Expected: 21

    # Test Case 4
    test4 = [[1, 0]]
    print(f"Test Case 4: {count_passengers(test4)}") # Expected: 1

    # Test Case 5
    test5 = []
    print(f"Test Case 5 (Empty): {count_passengers(test5)}") # Expected: 0