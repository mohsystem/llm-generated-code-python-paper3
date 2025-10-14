def is_valid_ip(ip_str: str) -> bool:
    """
    Validates if the given string is a valid IPv4 address.

    :param ip_str: The string to validate.
    :return: True if the string is a valid IPv4 address, False otherwise.
    """
    if not isinstance(ip_str, str):
        return False

    parts = ip_str.split('.')

    if len(parts) != 4:
        return False

    for part in parts:
        # Each part must not be empty. e.g., "1..2.3.4"
        if not part:
            return False
        
        # Each part must contain only digits.
        if not part.isdigit():
            return False

        # A part cannot have leading zeros unless it is "0" itself.
        if len(part) > 1 and part.startswith('0'):
            return False
        
        # The number must be in the range [0, 255].
        # The isdigit() check ensures int() will not raise a ValueError.
        num = int(part)
        if not (0 <= num <= 255):
            return False
            
    return True

def main():
    """ Main function with test cases. """
    test_cases = [
        "127.0.0.1",       # Valid
        "256.0.0.0",       # Invalid - range
        "192.168.01.1",    # Invalid - leading zero
        "1.2.3",           # Invalid - format/parts count
        "a.b.c.d"          # Invalid - non-numeric
    ]
    for ip in test_cases:
        result = "Valid" if is_valid_ip(ip) else "Invalid"
        print(f'IP: "{ip}" is {result}')

if __name__ == "__main__":
    main()