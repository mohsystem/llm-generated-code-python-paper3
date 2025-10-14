def count_passengers(stops):
    """
    Calculates the number of people still on the bus after the last bus stop.

    :param stops: A list of lists/tuples. Each inner list/tuple represents a bus stop
                  with two elements: (people_getting_on, people_getting_off).
    :return: The number of people remaining on the bus.
    """
    # Python's integers have arbitrary precision, preventing overflow.
    # The sum() with a generator expression is both efficient and idiomatic.
    return sum(on_bus - off_bus for on_bus, off_bus in stops)

if __name__ == '__main__':
    # Test Case 1
    print(count_passengers([[10, 0], [3, 5], [5, 8]]))

    # Test Case 2
    print(count_passengers([[3, 0], [9, 1], [4, 10], [12, 2], [6, 1], [7, 10]]))

    # Test Case 3: Single stop with no change
    print(count_passengers([[0, 0]]))

    # Test Case 4: Ends with zero passengers
    print(count_passengers([[100, 0], [0, 50], [25, 0], [0, 75]]))

    # Test Case 5: Net change is zero at most stops
    print(count_passengers([[5, 0], [5, 5], [5, 5], [5, 5], [5, 5]]))