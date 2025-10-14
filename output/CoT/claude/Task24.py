
def validate_pin(pin):
    # Null and type check
    if pin is None or not isinstance(pin, str):
        return False
    
    # Length validation - must be exactly 4 or 6
    length = len(pin)
    if length != 4 and length != 6:
        return False
    
    # Validate each character is a digit
    for char in pin:
        if not char.isdigit():
            return False
    
    return True


# Test cases
if __name__ == "__main__":
    print("Test 1 - '1234':", validate_pin("1234"))      # True
    print("Test 2 - '12345':", validate_pin("12345"))    # False
    print("Test 3 - 'a234':", validate_pin("a234"))      # False
    print("Test 4 - '123456':", validate_pin("123456"))  # True
    print("Test 5 - '':", validate_pin(""))              # False
