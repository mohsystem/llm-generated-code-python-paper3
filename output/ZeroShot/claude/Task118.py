
import re

def is_valid_ipv4(ip):
    if not ip:
        return False
    
    ipv4_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ipv4_pattern, ip))

def is_valid_ipv6(ip):
    if not ip:
        return False
    
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    ipv6_compressed_pattern = r'^(([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{0,4})?::([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{0,4}$'
    
    return bool(re.match(ipv6_pattern, ip)) or bool(re.match(ipv6_compressed_pattern, ip))

def validate_ip(ip):
    if is_valid_ipv4(ip):
        return "Valid IPv4"
    elif is_valid_ipv6(ip):
        return "Valid IPv6"
    else:
        return "Invalid IP"

if __name__ == "__main__":
    # Test cases
    test_cases = [
        "192.168.1.1",
        "256.1.1.1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "::1",
        "invalid.ip.address"
    ]
    
    print("IP Address Validation Results:")
    print("================================")
    for test_case in test_cases:
        print(f"IP: {test_case}")
        print(f"Result: {validate_ip(test_case)}")
        print("--------------------------------")
