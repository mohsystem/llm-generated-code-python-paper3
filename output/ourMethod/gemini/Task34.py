from typing import Union

def is_narcissistic(value: int) -> bool:
    """
    Checks if a number is a Narcissistic Number.
    A number is narcissistic if it is the sum of its own digits, each raised to
    the power of the number of digits.

    :param value: The positive integer to check.
    :return: True if the number is narcissistic, False otherwise.
    """
    s = str(value)
    num_digits = len(s)
    
    narcissistic_sum = sum(int(digit) ** num_digits for digit in s)
    
    return narcissistic_sum == value

if __name__ == '__main__':
    # 5 test cases
    print(f"is_narcissistic(153): {is_narcissistic(153)}")    # Expected: True
    print(f"is_narcissistic(1652): {is_narcissistic(1652)}")  # Expected: False
    print(f"is_narcissistic(7): {is_narcissistic(7)}")        # Expected: True
    print(f"is_narcissistic(371): {is_narcissistic(371)}")    # Expected: True
    print(f"is_narcissistic(123): {is_narcissistic(123)}")    # Expected: False