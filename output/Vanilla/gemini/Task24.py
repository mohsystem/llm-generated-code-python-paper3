def validate_pin(pin: str) -> bool:
    """
    Validates a PIN to be exactly 4 or 6 digits.
    :param pin: The PIN string to validate.
    :return: True if the PIN is valid, False otherwise.
    """
    return (len(pin) == 4 or len(pin) == 6) and pin.isdigit()

if __name__ == '__main__':
    # 5 test cases
    test_cases = ["1234", "12345", "a234", "123456", "123"]
    
    for pin in test_cases:
        result = str(validate_pin(pin)).lower()
        print(f'"{pin}"   -->  {result}')