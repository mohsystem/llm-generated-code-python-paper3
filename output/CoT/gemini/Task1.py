def count_passengers(stops):
    """
    Calculates the number of people remaining on the bus after all stops.

    Args:
        stops: A list of lists/tuples. Each inner list/tuple represents a stop
               with two elements: [people_getting_on, people_getting_off].
    
    Returns:
        The number of people on the bus after the last stop.
    """
    # The sum of a list comprehension on an empty list is 0,
    # so this naturally handles the empty case.
    return sum(on - off for on, off in stops)

# While Python doesn't require a main class, we can create one to meet the prompt's request.
class Task1:
    @staticmethod
    def main():
        # Test Case 1
        test1 = [[10, 0], [3, 5], [5, 8]]
        print(f"Test Case 1: {count_passengers(test1)}") # Expected: 5

        # Test Case 2
        test2 = [[3, 0], [9, 1], [4, 10], [12, 2], [6, 1], [7, 10]]
        print(f"Test Case 2: {count_passengers(test2)}") # Expected: 17

        # Test Case 3
        test3 = [[3, 0], [9, 1], [4, 8], [12, 2], [6, 1], [7, 8]]
        print(f"Test Case 3: {count_passengers(test3)}") # Expected: 21

        # Test Case 4: A single stop with no activity
        test4 = [[0, 0]]
        print(f"Test Case 4: {count_passengers(test4)}") # Expected: 0

        # Test Case 5: Empty list of stops
        test5 = []
        print(f"Test Case 5: {count_passengers(test5)}") # Expected: 0

if __name__ == '__main__':
    Task1.main()