def validate_pin(pin):
    """
    Validates an ATM PIN.
    A valid PIN must be exactly 4 or 6 digits long and contain only digits.

    :param pin: The string to validate.
    :return: True if the PIN is valid, False otherwise.
    """
    # Check if the length is either 4 or 6
    is_valid_length = len(pin) == 4 or len(pin) == 6
    # Check if all characters in the string are digits
    # The isdigit() method returns True for non-empty strings containing only digits.
    are_all_digits = pin.isdigit()
    
    return is_valid_length and are_all_digits

# main with test cases
if __name__ == '__main__':
    print("Testing Python version:")
    # Test Case 1: Valid 4-digit PIN
    print(f'"1234"   -->  {validate_pin("1234")}')
    # Test Case 2: Invalid length
    print(f'"12345"  -->  {validate_pin("12345")}')
    # Test Case 3: Invalid character
    print(f'"a234"   -->  {validate_pin("a234")}')
    # Test Case 4: Valid 6-digit PIN
    print(f'"451352" -->  {validate_pin("451352")}')
    # Test Case 5: Invalid characters and length
    print(f'"-1234"  -->  {validate_pin("-1234")}')