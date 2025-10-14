def validate_ip_address(ip_str):
    """
    Validates if the given string is a valid IPv4 or IPv6 address.
    """
    def is_ipv4(s):
        try:
            parts = s.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
                # Check for leading zeros, e.g., "01"
                if len(part) > 1 and part.startswith('0'):
                    return False
                # Check for non-digit characters (int() would catch this but being explicit is good)
                if not part.isdigit():
                    return False
            return True
        except (ValueError, TypeError):
            return False

    def is_ipv6(s):
        try:
            parts = s.split(':')
            if len(parts) != 8:
                return False
            for part in parts:
                if not (1 <= len(part) <= 4):
                    return False
                # Check if it's a valid hex number
                int(part, 16)
            return True
        except (ValueError, TypeError):
            return False

    if is_ipv4(ip_str):
        return "IPv4"
    elif is_ipv6(ip_str):
        return "IPv6"
    else:
        return "Neither"

if __name__ == '__main__':
    test_cases = [
        "172.16.254.1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "256.256.256.256",
        "192.168.01.1",
        "g:h:i:j:k:l:m:n"
    ]
    for ip in test_cases:
        print(f"IP: {ip} -> {validate_ip_address(ip)}")