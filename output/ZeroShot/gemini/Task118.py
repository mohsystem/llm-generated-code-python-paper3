import sys

def is_valid_ip(ip_str: str) -> bool:
    """
    Validates if the given string is a valid IPv4 address.
    A valid IPv4 address consists of four octets separated by dots.
    Each octet must be a number between 0 and 255.
    Leading zeros are not allowed, except for the number "0" itself.

    Args:
        ip_str: The string to validate.
    
    Returns:
        True if the string is a valid IPv4 address, False otherwise.
    """
    if not isinstance(ip_str, str):
        return False
        
    parts = ip_str.split('.')
    
    if len(parts) != 4:
        return False
        
    for part in parts:
        # Each part must not be empty (e.g., from "1..2.3.4").
        if not part:
            return False
            
        # Each part must consist of digits only.
        if not part.isdigit():
            return False
            
        # A part cannot have leading zeros unless it is just "0".
        if len(part) > 1 and part.startswith('0'):
            return False
            
        # The numeric value of the part must be between 0 and 255.
        num = int(part)
        if not (0 <= num <= 255):
            return False
            
    return True

if __name__ == "__main__":
    test_cases = [
        "192.168.1.1",      # Valid
        "255.255.255.255",  # Valid
        "0.0.0.0",          # Valid
        "1.2.3.4",          # Valid
        "192.168.1.256",    # Invalid: octet > 255
        "192.168.01.1",     # Invalid: leading zero
        "192.168.1",        # Invalid: too few parts
        "a.b.c.d",          # Invalid: non-numeric parts
        "1.2.3.4.",         # Invalid: trailing dot
        ".1.2.3.4",         # Invalid: leading dot
        "1..2.3.4"          # Invalid: consecutive dots
    ]
    
    for ip in test_cases:
        result = "valid" if is_valid_ip(ip) else "invalid"
        print(f"IP: {ip} is {result}")