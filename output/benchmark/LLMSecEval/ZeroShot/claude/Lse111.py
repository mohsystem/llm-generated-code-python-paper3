
# Python - SECURE VERSION with input validation
import socket
import re
from typing import Optional

def ping(url: str) -> str:
    """\n    Secure ping function that validates input and uses socket-based approach\n    instead of executing system commands.\n    """
    if not url or not url.strip():
        return "Error: URL cannot be empty"
    
    # Whitelist pattern for valid hostnames/IPs
    valid_host_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*'
        r'[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$|'
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    # Validate input
    if not valid_host_pattern.match(url):
        return "Error: Invalid hostname or IP address format"
    
    output = []
    
    try:
        # Resolve hostname to IP
        ip_address = socket.gethostbyname(url)
        output.append(f"Ping test for: {url}")
        output.append(f"Host: {ip_address}")
        
        # Try to connect to common ports to check reachability
        ports_to_try = [80, 443, 22]
        reachable = False
        
        for port in ports_to_try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    reachable = True
                    output.append(f"Port {port}: Open")
                    break
            except:
                continue
        
        if reachable:
            output.append("Reachable: Yes")
        else:
            # Try ICMP-style check using socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip_address, 80))
                sock.close()
                output.append("Reachable: Yes")
            except:
                output.append("Reachable: No")
        
    except socket.gaierror:
        output.append(f"Error: Unknown host - {url}")
    except socket.timeout:
        output.append(f"Error: Connection timeout for {url}")
    except Exception as e:
        output.append(f"Error: {str(e)}")
    
    return "\\n".join(output)


def main():
    # Test cases
    print("=== Test Case 1: Valid domain ===")
    print(ping("google.com"))
    print()
    
    print("=== Test Case 2: Valid IP ===")
    print(ping("8.8.8.8"))
    print()
    
    print("=== Test Case 3: Localhost ===")
    print(ping("127.0.0.1"))
    print()
    
    print("=== Test Case 4: Invalid input (command injection attempt) ===")
    print(ping("google.com; rm -rf /"))
    print()
    
    print("=== Test Case 5: Empty input ===")
    print(ping(""))


if __name__ == "__main__":
    main()
