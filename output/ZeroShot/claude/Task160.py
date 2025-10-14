
import urllib.request
import urllib.error
from urllib.parse import urlparse

ALLOWED_PROTOCOLS = {'http', 'https'}
BLOCKED_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.169.254'}
TIMEOUT = 5
MAX_RESPONSE_SIZE = 1048576  # 1MB

def make_http_request(url_string):
    try:
        # Parse and validate URL
        parsed_url = urlparse(url_string)
        
        # Check protocol
        if parsed_url.scheme.lower() not in ALLOWED_PROTOCOLS:
            return "Error: Only HTTP and HTTPS protocols are allowed"
        
        # Check for blocked hosts (SSRF protection)
        host = parsed_url.hostname
        if not host:
            return "Error: Invalid URL - no hostname"
        
        host_lower = host.lower()
        if (host_lower in BLOCKED_HOSTS or 
            host_lower.startswith('192.168.') or 
            host_lower.startswith('10.') or 
            host_lower.startswith('172.')):
            return "Error: Access to internal/private network addresses is blocked"
        
        # Make request
        request = urllib.request.Request(url_string)
        request.add_header('User-Agent', 'SecureHttpClient/1.0')
        
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            # Check response size
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > MAX_RESPONSE_SIZE:
                return "Error: Response size exceeds limit"
            
            # Read response
            data = response.read(MAX_RESPONSE_SIZE + 1)
            if len(data) > MAX_RESPONSE_SIZE:
                return "Error: Response size exceeds limit"
            
            response_text = data.decode('utf-8', errors='ignore')
            return f"Status Code: {response.status}\\nResponse:\\n{response_text}"
            
    except urllib.error.HTTPError as e:
        return f"HTTP Error: {e.code} - {e.reason}"
    except urllib.error.URLError as e:
        return f"URL Error: {e.reason}"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    print("HTTP Request Maker - Test Cases\\n")
    
    # Test case 1: Valid HTTPS URL
    print("Test 1: Valid HTTPS URL")
    result1 = make_http_request("https://www.example.com")
    print(result1[:200] + "...\\n")
    
    # Test case 2: Invalid protocol
    print("Test 2: Invalid protocol (file://)")
    result2 = make_http_request("file:///etc/passwd")
    print(result2 + "\\n")
    
    # Test case 3: Blocked host (localhost)
    print("Test 3: Blocked host (localhost)")
    result3 = make_http_request("http://localhost:8080")
    print(result3 + "\\n")
    
    # Test case 4: Blocked private IP
    print("Test 4: Blocked private IP")
    result4 = make_http_request("http://192.168.1.1")
    print(result4 + "\\n")
    
    # Test case 5: Invalid URL
    print("Test 5: Invalid URL")
    result5 = make_http_request("not-a-valid-url")
    print(result5 + "\\n")
