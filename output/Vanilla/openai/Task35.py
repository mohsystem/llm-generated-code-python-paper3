def count_people(stops):
    total = 0
    for on, off in stops:
        total += on - off
    return total

if __name__ == "__main__":
    test1 = [(10, 0), (3, 5), (5, 8)]  # Expected: 5
    test2 = [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)]  # Expected: 17
    test3 = [(0, 0)]  # Expected: 0
    test4 = [(5, 0), (5, 5), (10, 10), (1, 1)]  # Expected: 0
    test5 = [(50, 0), (30, 10), (5, 5), (40, 20), (0, 0), (1, 1)]  # Expected: 90

    print(count_people(test1))
    print(count_people(test2))
    print(count_people(test3))
    print(count_people(test4))
    print(count_people(test5))