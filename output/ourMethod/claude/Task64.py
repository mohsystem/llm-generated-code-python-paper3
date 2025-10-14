
import json
import sys
import urllib.request
import urllib.error
import ssl
from typing import Any, Dict
from urllib.parse import urlparse

MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB
CONNECTION_TIMEOUT = 10  # seconds


def fetch_and_parse_json(url_string: str) -> Any:
    """\n    Fetch JSON from a URL and parse it.\n    \n    Args:\n        url_string: The URL to fetch JSON from\n        \n    Returns:\n        Parsed JSON object\n        \n    Raises:\n        ValueError: If URL is invalid\n        RuntimeError: If fetch or parse fails\n    """
    if not url_string or not isinstance(url_string, str) or not url_string.strip():
        raise ValueError("URL cannot be None, empty, or non-string")
    
    # Validate URL format and scheme
    parsed_url = urlparse(url_string)
    if not parsed_url.scheme or parsed_url.scheme.lower() not in ('http', 'https'):
        raise ValueError("Only HTTP and HTTPS schemes are allowed")
    
    if not parsed_url.netloc:
        raise ValueError("Invalid URL format")
    
    # Create SSL context with certificate verification
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        # Create request with timeout
        request = urllib.request.Request(
            url_string,
            headers={'Accept': 'application/json'}
        )
        
        # Open connection with SSL context
        with urllib.request.urlopen(
            request,
            timeout=CONNECTION_TIMEOUT,
            context=ssl_context
        ) as response:
            
            # Check content length
            content_length = response.getheader('Content-Length')
            if content_length and int(content_length) > MAX_RESPONSE_SIZE:
                raise RuntimeError("Response size exceeds maximum allowed size")
            
            # Read response with size limit
            data = b''
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_RESPONSE_SIZE:
                    raise RuntimeError("Response size exceeds maximum allowed size")
            
            if not data:
                raise RuntimeError("Empty response received")
            
            # Decode and parse JSON
            json_string = data.decode('utf-8')
            return json.loads(json_string)
            
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP error: {e.code} - {e.reason}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"URL error: {str(e.reason)}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON: {str(e)}")
    except UnicodeDecodeError as e:
        raise RuntimeError(f"Encoding error: {str(e)}")


def main() -> None:
    """Main function with test cases."""
    
    # Test case 1: Valid JSON endpoint
    print("Test 1: Valid JSON URL")
    try:
        result = fetch_and_parse_json("https://jsonplaceholder.typicode.com/posts/1")
        print(f"Success: {json.dumps(result, indent=2)}")
    except Exception as e:
        print(f"Test 1 failed: {str(e)}")
    
    # Test case 2: None URL
    print("\\nTest 2: None URL")
    try:
        fetch_and_parse_json(None)
        print("Test should have failed")
    except Exception as e:
        print(f"Expected error: {str(e)}")
    
    # Test case 3: Empty URL
    print("\\nTest 3: Empty URL")
    try:
        fetch_and_parse_json("")
        print("Test should have failed")
    except Exception as e:
        print(f"Expected error: {str(e)}")
    
    # Test case 4: Invalid scheme
    print("\\nTest 4: Invalid scheme")
    try:
        fetch_and_parse_json("ftp://example.com/data.json")
        print("Test should have failed")
    except Exception as e:
        print(f"Expected error: {str(e)}")
    
    # Test case 5: Malformed URL
    print("\\nTest 5: Malformed URL")
    try:
        fetch_and_parse_json("not a valid url")
        print("Test should have failed")
    except Exception as e:
        print(f"Expected error: {str(e)}")


if __name__ == "__main__":
    main()
