
import re
from typing import Optional

IPV4_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

IPV6_PATTERN = re.compile(
    r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|"
    r"^([0-9a-fA-F]{1,4}:){1}:([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|"
    r"^([0-9a-fA-F]{1,4}:){2}:([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|"
    r"^([0-9a-fA-F]{1,4}:){3}:([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|"
    r"^([0-9a-fA-F]{1,4}:){4}:([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|"
    r"^([0-9a-fA-F]{1,4}:){5}:([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}$|"
    r"^([0-9a-fA-F]{1,4}:){6}:[0-9a-fA-F]{1,4}$|"
    r"^::$"
)

def is_valid_ipv4(ip: str) -> bool:
    if not ip or len(ip) > 15:
        return False
    return bool(IPV4_PATTERN.match(ip))

def is_valid_ipv6(ip: str) -> bool:
    if not ip or len(ip) > 39:
        return False
    return bool(IPV6_PATTERN.match(ip))

def validate_ip(ip: Optional[str]) -> str:
    if ip is None:
        return "Invalid: null input"
    
    if not ip:
        return "Invalid: empty input"
    
    if len(ip) > 100:
        return "Invalid: input too long"
    
    trimmed = ip.strip()
    
    if is_valid_ipv4(trimmed):
        return f"Valid IPv4: {trimmed}"
    elif is_valid_ipv6(trimmed):
        return f"Valid IPv6: {trimmed}"
    else:
        return f"Invalid IP address: {trimmed}"

def main():
    test_cases = [
        "192.168.1.1",
        "256.1.1.1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "::1",
        "invalid.ip.address"
    ]
    
    for test_case in test_cases:
        print(f'Input: "{test_case}" -> {validate_ip(test_case)}')

if __name__ == "__main__":
    main()
