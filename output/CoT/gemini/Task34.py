def narcissistic(value: int) -> bool:
    """
    Checks if a number is a Narcissistic Number (Armstrong Number).

    :param value: The positive integer to check.
    :return: True if the number is narcissistic, False otherwise.
    """
    # The prompt guarantees valid positive non-zero integers.
    s_value = str(value)
    num_digits = len(s_value)
    
    total_sum = 0
    temp = value
    while temp > 0:
        digit = temp % 10
        total_sum += digit ** num_digits
        temp //= 10
        
    return total_sum == value

# A more "Pythonic" one-liner implementation for reference:
# def narcissistic_pythonic(value):
#     return value == sum(int(digit) ** len(str(value)) for digit in str(value))

if __name__ == '__main__':
    print(f"Is 7 narcissistic? {narcissistic(7)}")      # Expected: True
    print(f"Is 153 narcissistic? {narcissistic(153)}")    # Expected: True
    print(f"Is 371 narcissistic? {narcissistic(371)}")    # Expected: True
    print(f"Is 1634 narcissistic? {narcissistic(1634)}")  # Expected: True
    print(f"Is 1652 narcissistic? {narcissistic(1652)}")  # Expected: False