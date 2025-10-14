
import re

def validate_ipv4(ip):
    """\n    Validates and processes IPv4 addresses\n    Prevents injection attacks and ensures strict validation\n    """
    if not ip or not isinstance(ip, str):
        return False
    
    # Prevent excessively long inputs (DoS prevention)
    if len(ip) > 15:
        return False
    
    # Strict regex pattern for IPv4 validation
    ipv4_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    if not re.match(ipv4_pattern, ip):
        return False
    
    # Additional validation: split and check each octet
    octets = ip.split('.')
    
    if len(octets) != 4:
        return False
    
    for octet in octets:
        try:
            value = int(octet)
            if value < 0 or value > 255:
                return False
            # Reject leading zeros (except for "0" itself)
            if len(octet) > 1 and octet[0] == '0':
                return False
        except ValueError:
            return False
    
    return True


def validate_ipv6(ip):
    """\n    Validates and processes IPv6 addresses\n    Prevents injection attacks and ensures strict validation\n    """
    if not ip or not isinstance(ip, str):
        return False
    
    # Prevent excessively long inputs (DoS prevention)
    if len(ip) > 39:
        return False
    
    # Strict regex pattern for IPv6 validation
    ipv6_pattern = (
        r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
        r'^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|'
        r'^([0-9a-fA-F]{1,4}:){1}:([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|'
        r'^([0-9a-fA-F]{1,4}:){2}:([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|'
        r'^([0-9a-fA-F]{1,4}:){3}:([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|'
        r'^([0-9a-fA-F]{1,4}:){4}:([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|'
        r'^([0-9a-fA-F]{1,4}:){5}:([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}$|'
        r'^([0-9a-fA-F]{1,4}:){6}:[0-9a-fA-F]{1,4}$|'
        r'^::$'
    )
    
    return bool(re.match(ipv6_pattern, ip))


def process_ip_address(ip):
    """\n    Determines IP version and validates accordingly\n    Returns: "Valid IPv4", "Valid IPv6", or "Invalid IP"\n    """
    if not ip or not isinstance(ip, str):
        return "Invalid IP"
    
    # Sanitize input - remove whitespace
    ip = ip.strip()
    
    # Prevent buffer overflow and DoS attacks
    if len(ip) > 100:
        return "Invalid IP"
    
    if validate_ipv4(ip):
        return "Valid IPv4"
    elif validate_ipv6(ip):
        return "Valid IPv6"
    else:
        return "Invalid IP"


def normalize_ipv4(ip):
    """\n    Normalizes IPv4 address (removes leading zeros safely)\n    """
    if not validate_ipv4(ip):
        return None
    
    octets = ip.split('.')
    normalized = '.'.join(str(int(octet)) for octet in octets)
    
    return normalized


if __name__ == "__main__":
    print("=== IP Address Validation Tests ===\\n")
    
    # Test Case 1: Valid IPv4
    test1 = "192.168.1.1"
    print(f"Test 1: {test1}")
    print(f"Result: {process_ip_address(test1)}")
    print(f"IPv4 Valid: {validate_ipv4(test1)}")
    print(f"Normalized: {normalize_ipv4(test1)}")
    print()
    
    # Test Case 2: Invalid IPv4 (out of range)
    test2 = "256.168.1.1"
    print(f"Test 2: {test2}")
    print(f"Result: {process_ip_address(test2)}")
    print(f"IPv4 Valid: {validate_ipv4(test2)}")
    print()
    
    # Test Case 3: Valid IPv6
    test3 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    print(f"Test 3: {test3}")
    print(f"Result: {process_ip_address(test3)}")
    print(f"IPv6 Valid: {validate_ipv6(test3)}")
    print()
    
    # Test Case 4: Invalid IP (malicious input attempt)
    test4 = "192.168.1.1; DROP TABLE users;"
    print(f"Test 4: {test4}")
    print(f"Result: {process_ip_address(test4)}")
    print(f"IPv4 Valid: {validate_ipv4(test4)}")
    print()
    
    # Test Case 5: Edge case (localhost)
    test5 = "127.0.0.1"
    print(f"Test 5: {test5}")
    print(f"Result: {process_ip_address(test5)}")
    print(f"IPv4 Valid: {validate_ipv4(test5)}")
    print(f"Normalized: {normalize_ipv4(test5)}")
    print()
