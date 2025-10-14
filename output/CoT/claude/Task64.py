
import json
import sys
import urllib.request
import urllib.error
from urllib.parse import urlparse

MAX_SIZE = 10 * 1024 * 1024  # 10 MB
TIMEOUT = 10  # seconds
ALLOWED_PROTOCOLS = ['http', 'https']

def fetch_and_parse_json(url_string):
    """\n    Securely fetch and parse JSON from a URL\n    \n    Args:\n        url_string: The URL to fetch JSON from\n        \n    Returns:\n        Parsed JSON object (dict)\n        \n    Raises:\n        ValueError: If URL is invalid or empty\n        SecurityError: If security check fails\n        Exception: For other errors\n    """
    # Input validation
    if not url_string or not url_string.strip():
        raise ValueError("URL cannot be None or empty")
    
    # Parse and validate URL
    parsed_url = urlparse(url_string)
    protocol = parsed_url.scheme.lower()
    
    if protocol not in ALLOWED_PROTOCOLS:
        raise SecurityError("Only HTTP and HTTPS protocols are allowed")
    
    # Prevent SSRF attacks - block private IP ranges
    hostname = parsed_url.hostname
    if hostname:
        hostname_lower = hostname.lower()
        if (hostname_lower in ['localhost', '127.0.0.1', '0.0.0.0'] or
            hostname_lower.startswith('192.168.') or
            hostname_lower.startswith('10.') or
            hostname_lower.startswith('172.16.')):
            raise SecurityError("Access to private network addresses is not allowed")
    
    try:
        # Create request with security headers
        request = urllib.request.Request(
            url_string,
            headers={
                'User-Agent': 'SecureJSONFetcher/1.0',
                'Accept': 'application/json'
            }
        )
        
        # Fetch content with timeout
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            # Check content type
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' not in content_type and 'text/plain' not in content_type:
                if content_type:
                    raise SecurityError(f"Invalid content type: {content_type}")
            
            # Read with size limit
            content = response.read(MAX_SIZE + 1)
            if len(content) > MAX_SIZE:
                raise SecurityError("Response size exceeds maximum allowed size")
            
            # Decode and parse JSON
            json_string = content.decode('utf-8')
            json_object = json.loads(json_string)
            
            return json_object
            
    except urllib.error.URLError as e:
        raise Exception(f"Failed to fetch URL: {str(e)}")
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse JSON: {str(e)}")
    except Exception as e:
        raise Exception(f"Error: {str(e)}")

class SecurityError(Exception):
    pass

def main():
    # Test cases with safe public URLs
    test_urls = [
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://api.github.com/users/github",
        "https://jsonplaceholder.typicode.com/users/1",
        "https://jsonplaceholder.typicode.com/todos/1",
        "https://jsonplaceholder.typicode.com/comments/1"
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"\\nTest Case {i}:")
        print(f"URL: {url}")
        try:
            result = fetch_and_parse_json(url)
            print(f"Result: {json.dumps(result, indent=2)}")
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
