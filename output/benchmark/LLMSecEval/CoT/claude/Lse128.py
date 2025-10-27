
import re
import html
from io import StringIO

MAX_USERNAME_LENGTH = 100
SAFE_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\- ]{1,100}$')

def http_hello_page(request, response):
    """\n    Processes HTTP request and generates hello response\n    \n    Args:\n        request: Input stream containing HTTP request\n        response: Output stream for HTTP response\n    \n    Returns:\n        str: The hello message\n    """
    username = extract_username(request)
    
    if not username or not username.strip():
        username = "Guest"
    
    # Sanitize username
    username = sanitize_input(username)
    
    # Construct HTTP response
    message = f"hello {html_encode(username)}"
    
    response.write("HTTP/1.1 200 OK\\r\\n")
    response.write("Content-Type: text/html; charset=UTF-8\\r\\n")
    response.write(f"Content-Length: {len(message)}\\r\\n")
    response.write("\\r\\n")
    response.write(message)
    response.flush()
    
    return message

def extract_username(request):
    """Extract username from request stream"""
    try:
        for line in request:
            line = line.strip()
            if line.lower().startswith("username:"):
                return line[9:].strip()
    except:
        pass
    return "Guest"

def sanitize_input(input_str):
    """Sanitize user input to prevent injection attacks"""
    if not input_str:
        return ""
    
    # Limit length
    if len(input_str) > MAX_USERNAME_LENGTH:
        input_str = input_str[:MAX_USERNAME_LENGTH]
    
    # Allow only safe characters
    if not SAFE_USERNAME_PATTERN.match(input_str):
        input_str = re.sub(r'[^a-zA-Z0-9_\\- ]', '', input_str)
    
    return input_str.strip()

def html_encode(input_str):
    """HTML encode to prevent XSS"""
    if not input_str:
        return ""
    
    return (input_str.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .replace('"', "&quot;")
                     .replace("'", "&#x27;")
                     .replace("/", "&#x2F;"))

def main():
    """Test cases"""
    test_cases = [
        ("username: John", "hello John"),
        ("", "hello Guest"),
        ("username: <script>alert('xss')</script>", "hello scriptalertxssscript"),
        ("username: " + "a" * 150, "hello " + "a" * 100),
        ("username: admin' OR '1'='1", "hello admin OR 11")
    ]
    
    for request_data, expected in test_cases:
        request = StringIO(request_data)
        response = StringIO()
        
        result = http_hello_page(request, response)
        print(f"Input: {request_data}")
        print(f"Output: {result}")
        print(f"Expected: {expected}")
        print("---")

if __name__ == "__main__":
    main()
