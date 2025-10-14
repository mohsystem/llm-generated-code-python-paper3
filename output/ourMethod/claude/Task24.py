
def validate_pin(pin: str) -> bool:
    """\n    Validates if a PIN is exactly 4 or 6 digits.\n    \n    Args:\n        pin: The PIN string to validate\n        \n    Returns:\n        True if valid, False otherwise\n    """
    # Validate input is not None
    if pin is None:
        return False
    
    # Check length is exactly 4 or 6
    length = len(pin)
    if length != 4 and length != 6:
        return False
    
    # Validate each character is a digit
    for char in pin:
        if char < '0' or char > '9':
            return False
    
    return True


if __name__ == "__main__":
    # Test case 1: Valid 4-digit PIN
    print(validate_pin("1234"))  # True
    
    # Test case 2: Invalid 5-digit PIN
    print(validate_pin("12345"))  # False
    
    # Test case 3: Invalid PIN with letter
    print(validate_pin("a234"))  # False
    
    # Test case 4: Valid 6-digit PIN
    print(validate_pin("123456"))  # True
    
    # Test case 5: None input
    print(validate_pin(None))  # False
