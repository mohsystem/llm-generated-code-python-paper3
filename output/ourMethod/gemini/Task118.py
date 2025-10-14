import typing

def is_valid_ipv4(ip: str) -> bool:
    """
    Validates if a given string is a valid IPv4 address.

    An IPv4 address is valid if it consists of four octets separated by dots,
    where each octet is a decimal number from 0 to 255.
    Leading zeros are not allowed (e.g., "01" is invalid), except for the number "0" itself.

    Args:
        ip: The string to validate.

    Returns:
        True if the string is a valid IPv4 address, False otherwise.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(ip, str):
        return False
        
    octets = ip.split('.')

    if len(octets) != 4:
        return False

    for octet_str in octets:
        # Check for non-digit characters and empty strings
        if not octet_str.isdigit():
            return False

        # Check for leading zeros, e.g., "01". "0" is allowed.
        if len(octet_str) > 1 and octet_str.startswith('0'):
            return False

        # Rule #6: Handle potential exceptions from parsing (covered by isdigit).
        # Convert to integer and check range
        octet_value = int(octet_str)
        if not (0 <= octet_value <= 255):
            return False

    return True

def main():
    """Main function with test cases."""
    test_cases = [
        "192.168.1.1",       # Valid
        "256.0.0.1",         # Invalid range
        "192.168.01.1",      # Invalid leading zero
        "192.168.1.a",       # Invalid character
        "1.2.3"              # Invalid structure (too few parts)
    ]

    for ip in test_cases:
        print(f'Is "{ip}" a valid IPv4 address? {is_valid_ipv4(ip)}')
        
    print("\n--- Additional Test Cases ---")
    more_test_cases = [
        "0.0.0.0",           # Valid
        "255.255.255.255",   # Valid
        "1.2.3.4.5",         # Invalid structure (too many parts)
        "1..2.3.4",          # Invalid structure (empty octet)
        "1.2.3.",            # Invalid structure (trailing dot)
        "",                  # Invalid empty string
        "123.45.67.89"       # Valid
    ]

    for ip in more_test_cases:
        print(f'Is "{ip}" a valid IPv4 address? {is_valid_ipv4(ip)}')


if __name__ == '__main__':
    main()