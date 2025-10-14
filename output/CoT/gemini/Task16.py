def solution(string, ending):
    """
    Checks if the first string ends with the second string.

    :param string: The main string.
    :param ending: The string to check for at the end of the main string.
    :return: True if the string ends with the ending, False otherwise.
    """
    if not isinstance(string, str) or not isinstance(ending, str):
        return False
    return string.endswith(ending)

if __name__ == '__main__':
    # Test cases
    test_cases = [
        ("abc", "bc", True),
        ("abc", "d", False),
        ("samurai", "ai", True),
        ("abc", "", True),
        ("abc", "abcde", False)
    ]

    for i, (str_val, end_val, expected) in enumerate(test_cases):
        print(f"Test Case {i + 1}: solution(\"{str_val}\", \"{end_val}\")")
        print(f"Expected: {expected}")
        actual = solution(str_val, end_val)
        print(f"Actual: {actual}")
        print()