def validate_pin(pin: str) -> bool:
    """
    Validates a PIN according to the rules:
    - Must be exactly 4 or 6 digits long.
    - Must contain only numeric digits.

    :param pin: The PIN string to validate.
    :return: True if the PIN is valid, False otherwise.
    """
    # Check if the pin consists of digits and its length is either 4 or 6.
    return isinstance(pin, str) and (len(pin) == 4 or len(pin) == 6) and pin.isdigit()

if __name__ == '__main__':
    # Test cases
    test_pins = [
        "1234",    # True
        "12345",   # False
        "a234",    # False
        "123456",  # True
        "12.0"     # False
    ]

    print("Python Test Cases:")
    for pin in test_pins:
        print(f'"{pin}" --> {validate_pin(pin)}')