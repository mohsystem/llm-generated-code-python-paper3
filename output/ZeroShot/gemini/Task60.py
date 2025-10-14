def expanded_form(num):
    """
    Converts a positive number into its expanded form string.

    :param num: The number to convert, must be an integer > 0.
    :return: The expanded form of the number as a string.
    """
    # According to the problem description, num will be > 0.
    # Adding a check for robustness.
    if not isinstance(num, int) or num <= 0:
        return ""

    s = str(num)
    parts = []
    length = len(s)
    for i, digit in enumerate(s):
        if digit != '0':
            num_zeros = length - 1 - i
            part = digit + '0' * num_zeros
            parts.append(part)
    return " + ".join(parts)

if __name__ == '__main__':
    # Test Cases
    print(f"12 -> {expanded_form(12)}")  # Expected: 10 + 2
    print(f"42 -> {expanded_form(42)}")  # Expected: 40 + 2
    print(f"70304 -> {expanded_form(70304)}")  # Expected: 70000 + 300 + 4
    print(f"9000000 -> {expanded_form(9000000)}")  # Expected: 9000000
    print(f"1 -> {expanded_form(1)}")  # Expected: 1