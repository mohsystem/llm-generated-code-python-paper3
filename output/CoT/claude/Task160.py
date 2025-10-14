
import socket
import re
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import ipaddress

TIMEOUT = 5  # seconds
MAX_RESPONSE_SIZE = 1048576  # 1MB

def make_http_request(url_string):
    """\n    Makes a secure HTTP request to the provided URL\n    """
    # Validate URL
    if not url_string or not url_string.strip():
        return "Error: URL cannot be empty"
    
    try:
        parsed_url = urlparse(url_string)
        
        # Security: Only allow HTTP and HTTPS protocols
        if parsed_url.scheme.lower() not in ['http', 'https']:
            return "Error: Only HTTP and HTTPS protocols are allowed"
        
        # Security: Block requests to private/internal IP addresses
        if is_private_or_local_address(parsed_url.hostname):
            return "Error: Requests to private/internal addresses are not allowed"
        
        # Make HTTP request with security settings
        request = Request(url_string)
        request.add_header('User-Agent', 'SecureHttpClient/1.0')
        
        with urlopen(request, timeout=TIMEOUT) as response:
            # Read response with size limit
            content = response.read(MAX_RESPONSE_SIZE)
            if len(content) >= MAX_RESPONSE_SIZE:
                return "Error: Response size exceeds limit"
            
            status_code = response.getcode()
            return f"Status: {status_code}\\n{content.decode('utf-8', errors='ignore')}"
            
    except ValueError as e:
        return f"Error: Invalid URL format - {str(e)}"
    except socket.timeout:
        return "Error: Request timeout"
    except HTTPError as e:
        return f"Error: HTTP {e.code} - {e.reason}"
    except URLError as e:
        return f"Error: {str(e.reason)}"
    except Exception as e:
        return f"Error: {str(e)}"

def is_private_or_local_address(hostname):
    """\n    Check if hostname is a private or local address\n    """
    if not hostname:
        return True
    
    # Block common localhost names
    blocked_hosts = ['localhost', '0.0.0.0']
    if hostname.lower() in blocked_hosts:
        return True
    
    try:
        # Resolve hostname to IP and check if it's private
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        return (ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or
                ip_obj.is_reserved)
    except (socket.gaierror, ValueError):
        return False

if __name__ == "__main__":
    print("=== Test Case 1: Valid HTTPS URL ===")
    print(make_http_request("https://www.example.com"))
    
    print("\\n=== Test Case 2: Invalid Protocol ===")
    print(make_http_request("ftp://example.com"))
    
    print("\\n=== Test Case 3: Localhost (blocked) ===")
    print(make_http_request("http://localhost:8080"))
    
    print("\\n=== Test Case 4: Private IP (blocked) ===")
    print(make_http_request("http://192.168.1.1"))
    
    print("\\n=== Test Case 5: Empty URL ===")
    print(make_http_request(""))
