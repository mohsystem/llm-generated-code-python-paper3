
def clean_phone_number(phone_number):
    if phone_number is None:
        return None
    
    # Remove all non-digit characters
    digits_only = ''.join(filter(str.isdigit, phone_number))
    
    # Check if empty after cleaning
    if not digits_only:
        return None
    
    # Handle country code 1
    if len(digits_only) == 11 and digits_only[0] == '1':
        digits_only = digits_only[1:]
    
    # Validate length
    if len(digits_only) != 10:
        return None
    
    # Validate NANP format: NXX NXX-XXXX
    # First digit of area code (N) must be 2-9
    if digits_only[0] < '2' or digits_only[0] > '9':
        return None
    
    # Fourth digit (first digit of exchange code) must be 2-9
    if digits_only[3] < '2' or digits_only[3] > '9':
        return None
    
    return digits_only


if __name__ == "__main__":
    # Test case 1: Phone number with country code and special characters
    print("Test 1:", clean_phone_number("+1 (613)-995-0253"))
    
    # Test case 2: Phone number with dashes
    print("Test 2:", clean_phone_number("613-995-0253"))
    
    # Test case 3: Phone number with country code and spaces
    print("Test 3:", clean_phone_number("1 613 995 0253"))
    
    # Test case 4: Phone number with dots
    print("Test 4:", clean_phone_number("613.995.0253"))
    
    # Test case 5: Phone number with parentheses
    print("Test 5:", clean_phone_number("(234) 567-8901"))
