
def clean_phone_number(phone_number):
    if phone_number is None:
        return None
    
    # Remove all non-digit characters
    digits_only = ''.join(filter(str.isdigit, phone_number))
    
    # Check if it starts with country code 1 and has 11 digits
    if len(digits_only) == 11 and digits_only.startswith('1'):
        digits_only = digits_only[1:]
    
    # Validate the cleaned number
    if len(digits_only) != 10:
        return None
    
    # Validate area code (first digit must be 2-9)
    if digits_only[0] < '2' or digits_only[0] > '9':
        return None
    
    # Validate exchange code (first digit must be 2-9)
    if digits_only[3] < '2' or digits_only[3] > '9':
        return None
    
    return digits_only

if __name__ == "__main__":
    # Test cases
    print("Test 1:", clean_phone_number("+1 (613)-995-0253"))
    print("Test 2:", clean_phone_number("613-995-0253"))
    print("Test 3:", clean_phone_number("1 613 995 0253"))
    print("Test 4:", clean_phone_number("613.995.0253"))
    print("Test 5:", clean_phone_number("(234) 567-8901"))
