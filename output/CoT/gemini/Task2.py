def create_phone_number(numbers):
    """
    Accepts a list of 10 integers (between 0 and 9) and returns a string
    of those numbers in the form of a phone number.

    :param numbers: A list of 10 integers (0-9).
    :return: A formatted phone number string, e.g., "(123) 456-7890".
    """
    # Input validation to ensure the list has the correct length.
    if not isinstance(numbers, list) or len(numbers) != 10:
        raise ValueError("Input must be a list containing exactly 10 integers.")

    # Use a format string for a clean, readable, and safe implementation.
    # The '*' operator unpacks the list elements into arguments for format().
    return "({}{}{}) {}{}{}-{}{}{}{}".format(*numbers)

# Main execution block with 5 test cases
if __name__ == "__main__":
    test_cases = [
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        [0, 9, 8, 7, 6, 5, 4, 3, 2, 1],
        [5, 5, 5, 8, 6, 7, 5, 3, 0, 9],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ]

    for i, case in enumerate(test_cases, 1):
        try:
            phone_number = create_phone_number(case)
            print(f"Test Case {i}: {phone_number}")
        except ValueError as e:
            print(f"Test Case {i}: Error - {e}")