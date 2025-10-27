
import subprocess
import re
from typing import Optional

# Whitelist pattern: only allow valid hostnames and IP addresses
VALID_HOST_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$|'
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

MAX_HOST_LENGTH = 253


def ping(url: str) -> str:
    """\n    Simulates a web endpoint that pings a host.\n    SECURITY: Uses strict input validation to prevent command injection.\n    Only allows validated hostnames/IPs, no shell metacharacters.\n    \n    Args:\n        url: The hostname or IP address to ping\n        \n    Returns:\n        The output of the ping command or an error message\n    """
    # Input validation: reject None or empty
    if not url or not url.strip():
        return "Error: Invalid input"
    
    url = url.strip()
    
    # Length validation: prevent excessively long inputs
    if len(url) > MAX_HOST_LENGTH:
        return "Error: Invalid input"
    
    # Whitelist validation: only allow valid hostnames/IPs
    # This prevents command injection by rejecting shell metacharacters
    if not VALID_HOST_PATTERN.match(url):
        return "Error: Invalid input"
    
    try:
        # Use subprocess with list arguments (no shell interpretation)
        # shell=False prevents command injection as no shell is invoked
        # capture_output and text handle I/O safely
        result = subprocess.run(
            ['ping', '-c', '4', url],
            capture_output=True,
            text=True,
            timeout=10,  # Timeout to prevent hanging
            shell=False  # Critical: never use shell=True with user input
        )
        
        # Combine stdout and stderr
        output = result.stdout
        if result.stderr:
            output += result.stderr
            
        return output
        
    except subprocess.TimeoutExpired:
        # Generic error - don't leak internal details\n        return "Error: Operation timeout"\n    except Exception:\n        # Generic error - don't leak internal details
        return "Error: Operation failed"


if __name__ == "__main__":
    # Test case 1: Valid hostname
    print("Test 1 - Valid hostname:")
    print(ping("localhost"))
    
    # Test case 2: Valid IP address
    print("\\nTest 2 - Valid IP:")
    print(ping("127.0.0.1"))
    
    # Test case 3: Command injection attempt (rejected)
    print("\\nTest 3 - Injection attempt:")
    print(ping("localhost; cat /etc/passwd"))
    
    # Test case 4: Invalid input with special characters
    print("\\nTest 4 - Special characters:")
    print(ping("host`whoami`"))
    
    # Test case 5: Empty input
    print("\\nTest 5 - Empty input:")
    print(ping(""))
