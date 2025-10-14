def create_phone_number(n):
    return "({}{}{}) {}{}{}-{}{}{}{}".format(*n)

if __name__ == '__main__':
    # Test cases
    test_cases = [
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        [8, 0, 0, 5, 5, 5, 1, 2, 3, 4],
        [0, 9, 8, 7, 6, 5, 4, 3, 2, 1],
        [5, 1, 9, 5, 5, 5, 4, 4, 6, 8]
    ]

    for test_case in test_cases:
        print(create_phone_number(test_case))