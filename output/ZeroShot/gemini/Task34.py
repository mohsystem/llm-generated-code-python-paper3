def is_narcissistic(value: int) -> bool:
    """
    Checks if a number is a Narcissistic Number.
    A Narcissistic Number is a positive number which is the sum of its own digits,
    each raised to the power of the number of digits.
    :param value: The positive integer to check.
    :return: True if the number is narcissistic, False otherwise.
    """
    if not isinstance(value, int) or value <= 0:
        return False
    
    s_value = str(value)
    num_digits = len(s_value)
    
    sum_of_powers = sum(int(digit) ** num_digits for digit in s_value)
        
    return sum_of_powers == value

if __name__ == '__main__':
    test_cases = [153, 1652, 7, 371, 9474]
    for test_case in test_cases:
        # Python's bools print as True/False, which is fine.
        # To get lowercase, we would do str(is_narcissistic(test_case)).lower()
        print(f"is_narcissistic({test_case}) -> {is_narcissistic(test_case)}")