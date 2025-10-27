
import sys
from typing import BinaryIO

# Maximum allowed lengths to prevent resource exhaustion
MAX_USERNAME_LENGTH = 100
MAX_REQUEST_SIZE = 1024


def http_hello_page(request: BinaryIO, response: BinaryIO) -> None:
    """\n    Processes HTTP request and sends greeting response\n    \n    Args:\n        request: Input stream containing the client request\n        response: Output stream for sending response to client\n    """
    if request is None or response is None:
        raise ValueError("Request and response streams cannot be None")
    
    # Read request with size limit to prevent memory exhaustion
    request_data = request.read(MAX_REQUEST_SIZE)
    
    # Decode using UTF-8, replacing invalid sequences
    try:
        request_str = request_data.decode('utf-8', errors='replace')
    except Exception:
        request_str = ""
    
    # Extract username - validate and sanitize input
    username = extract_username(request_str)
    
    # Validate username length
    if len(username) > MAX_USERNAME_LENGTH:
        username = username[:MAX_USERNAME_LENGTH]
    
    # Sanitize username to prevent injection attacks
    username = sanitize_username(username)
    
    # Construct response with sanitized data
    response_message = f"Hello {username}"
    
    # Write response using safe UTF-8 encoding
    response.write(response_message.encode('utf-8'))
    response.flush()


def extract_username(request: str) -> str:
    """\n    Extracts username from request string\n    \n    Args:\n        request: The request string\n        \n    Returns:\n        Extracted username or "Guest" if not found\n    """
    if not request:
        return "Guest"
    
    # Simple extraction - look for username parameter
    # Format expected: username=value
    parts = request.split("username=")
    if len(parts) < 2:
        return "Guest"
    
    # Get username portion and stop at first delimiter
    username_part = parts[1]
    
    # Find end of username (at delimiter or end of string)
    for delimiter in ['&', '\\n', '\\r']:
        idx = username_part.find(delimiter)
        if idx != -1:
            username_part = username_part[:idx]
            break
    
    return username_part.strip()


def sanitize_username(username: str) -> str:
    """\n    Sanitizes username to prevent injection attacks\n    Removes potentially dangerous characters\n    \n    Args:\n        username: The username to sanitize\n        \n    Returns:\n        Sanitized username\n    """
    if not username:
        return "Guest"
    
    # Allow only alphanumeric characters, spaces, hyphens, and underscores
    # Remove all other characters to prevent injection
    sanitized = ''.join(c for c in username 
                       if c.isalnum() or c in ' -_')
    
    sanitized = sanitized.strip()
    return sanitized if sanitized else "Guest"


def main():
    """Test cases for http_hello_page function"""
    import io
    
    # Test case 1: Normal username
    try:
        req1 = io.BytesIO(b"username=Alice")
        resp1 = io.BytesIO()
        http_hello_page(req1, resp1)
        print(f"Test 1: {resp1.getvalue().decode('utf-8')}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Username with special characters (should be sanitized)
    try:
        req2 = io.BytesIO(b"username=Bob<script>")
        resp2 = io.BytesIO()
        http_hello_page(req2, resp2)
        print(f"Test 2: {resp2.getvalue().decode('utf-8')}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: No username provided
    try:
        req3 = io.BytesIO(b"other=data")
        resp3 = io.BytesIO()
        http_hello_page(req3, resp3)
        print(f"Test 3: {resp3.getvalue().decode('utf-8')}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Very long username (should be truncated)
    try:
        long_name = b"username=" + b"A" * 200
        req4 = io.BytesIO(long_name)
        resp4 = io.BytesIO()
        http_hello_page(req4, resp4)
        print(f"Test 4: {resp4.getvalue().decode('utf-8')}")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: Username with valid special characters
    try:
        req5 = io.BytesIO(b"username=John_Doe-123")
        resp5 = io.BytesIO()
        http_hello_page(req5, resp5)
        print(f"Test 5: {resp5.getvalue().decode('utf-8')}")
    except Exception as e:
        print(f"Test 5 failed: {e}")


if __name__ == "__main__":
    main()
