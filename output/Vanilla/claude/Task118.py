
import re

def is_valid_ipv4(ip):
    if not ip:
        return False
    
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    for part in parts:
        if not part or len(part) > 3:
            return False
        
        # Check for leading zeros
        if len(part) > 1 and part[0] == '0':
            return False
        
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    
    return True

def is_valid_ipv6(ip):
    if not ip:
        return False
    
    parts = ip.split(':')
    if len(parts) > 8 or len(parts) < 3:
        return False
    
    has_double_colon = '::' in ip
    if has_double_colon:
        if ip.count('::') > 1:
            return False
    
    for part in parts:
        if not part and has_double_colon:
            continue
        if len(part) > 4:
            return False
        if not re.match(r'^[0-9a-fA-F]*$', part):
            return False
    
    return True

def get_ip_version(ip):
    if is_valid_ipv4(ip):
        return "IPv4"
    elif is_valid_ipv6(ip):
        return "IPv6"
    else:
        return "Invalid"

def normalize_ipv4(ip):
    if not is_valid_ipv4(ip):
        return "Invalid IP"
    return ip

if __name__ == "__main__":
    # Test case 1: Valid IPv4
    test1 = "192.168.1.1"
    print(f"Test 1: {test1}")
    print(f"Valid IPv4: {is_valid_ipv4(test1)}")
    print(f"IP Version: {get_ip_version(test1)}")
    print()
    
    # Test case 2: Invalid IPv4 (out of range)
    test2 = "256.168.1.1"
    print(f"Test 2: {test2}")
    print(f"Valid IPv4: {is_valid_ipv4(test2)}")
    print(f"IP Version: {get_ip_version(test2)}")
    print()
    
    # Test case 3: Valid IPv6
    test3 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    print(f"Test 3: {test3}")
    print(f"Valid IPv6: {is_valid_ipv6(test3)}")
    print(f"IP Version: {get_ip_version(test3)}")
    print()
    
    # Test case 4: IPv6 with double colon
    test4 = "2001:db8::8a2e:370:7334"
    print(f"Test 4: {test4}")
    print(f"Valid IPv6: {is_valid_ipv6(test4)}")
    print(f"IP Version: {get_ip_version(test4)}")
    print()
    
    # Test case 5: Invalid IP
    test5 = "invalid.ip.address"
    print(f"Test 5: {test5}")
    print(f"Valid IPv4: {is_valid_ipv4(test5)}")
    print(f"Valid IPv6: {is_valid_ipv6(test5)}")
    print(f"IP Version: {get_ip_version(test5)}")
    print()
