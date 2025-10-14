def is_narcissistic(value: int) -> bool:
    """
    Checks if a given number is a Narcissistic Number (Armstrong Number).

    :param value: The positive integer to check.
    :return: True if the number is narcissistic, False otherwise.
    """
    if value <= 0:
        return False
        
    s = str(value)
    num_digits = len(s)
    
    sum_of_powers = sum(int(digit) ** num_digits for digit in s)
    
    return sum_of_powers == value

if __name__ == '__main__':
    test_cases = [153, 1652, 1, 371, 9474]
    for test_case in test_cases:
        print(is_narcissistic(test_case))