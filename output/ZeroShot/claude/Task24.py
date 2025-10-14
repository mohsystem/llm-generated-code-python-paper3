
def validate_pin(pin):
    if pin is None:
        return False
    
    length = len(pin)
    if length != 4 and length != 6:
        return False
    
    for char in pin:
        if not char.isdigit():
            return False
    
    return True

if __name__ == "__main__":
    # Test cases
    print(validate_pin("1234"))   # True
    print(validate_pin("123456")) # True
    print(validate_pin("12345"))  # False
    print(validate_pin("a234"))   # False
    print(validate_pin(""))       # False
