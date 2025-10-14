
import re
import urllib.parse
import urllib.request
import socket
from typing import Optional

MAX_URL_LENGTH = 2048
TIMEOUT_SECONDS = 5
ALLOWED_SCHEMES = {'http', 'https'}
URL_PATTERN = re.compile(
    r'^(https?)://([a-zA-Z0-9.-]+)(:[0-9]{1,5})?(/[^\\s]*)?$'
)

def make_http_request(url_string: Optional[str]) -> str:
    if url_string is None or not url_string.strip():
        return "Error: URL cannot be null or empty"
    
    url_string = url_string.strip()
    
    if len(url_string) > MAX_URL_LENGTH:
        return "Error: URL exceeds maximum length"
    
    if not URL_PATTERN.match(url_string):
        return "Error: Invalid URL format"
    
    try:
        parsed = urllib.parse.urlparse(url_string)
        
        scheme = parsed.scheme.lower() if parsed.scheme else None
        if scheme not in ALLOWED_SCHEMES:
            return "Error: Only HTTP and HTTPS schemes are allowed"
        
        host = parsed.hostname
        if not host:
            return "Error: Invalid host"
        
        host_lower = host.lower()
        if (host_lower == 'localhost' or 
            host_lower == '127.0.0.1' or 
            host_lower.startswith('192.168.') or 
            host_lower.startswith('10.') or 
            host_lower.startswith('172.16.') or 
            host_lower == '0.0.0.0'):
            return "Error: Access to local/private network addresses is not allowed"
        
        req = urllib.request.Request(
            url_string,
            headers={'User-Agent': 'SecureHttpClient/1.0'}
        )
        
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            response_code = response.getcode()
            content = response.read().decode('utf-8', errors='replace')
            
            lines = content.split('\\n')
            max_lines = 1000
            if len(lines) > max_lines:
                lines = lines[:max_lines]
            
            return f"Response Code: {response_code}\\n" + '\\n'.join(lines)
    
    except urllib.error.HTTPError as e:
        return f"Error: HTTP response code {e.code}"
    except urllib.error.URLError as e:
        return f"Error: URL error - {type(e.reason).__name__}"
    except socket.timeout:
        return "Error: Connection timeout"
    except ValueError:
        return "Error: Invalid URL"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def main() -> None:
    print("Test 1 - Valid HTTPS URL:")
    print(make_http_request("https://www.example.com"))
    print()
    
    print("Test 2 - Invalid scheme:")
    print(make_http_request("ftp://example.com"))
    print()
    
    print("Test 3 - Localhost blocked:")
    print(make_http_request("http://localhost:8080"))
    print()
    
    print("Test 4 - Empty URL:")
    print(make_http_request(""))
    print()
    
    print("Test 5 - Invalid format:")
    print(make_http_request("not a valid url"))

if __name__ == "__main__":
    main()
