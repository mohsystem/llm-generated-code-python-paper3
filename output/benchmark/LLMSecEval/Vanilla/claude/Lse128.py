
import re
from io import StringIO
from urllib.parse import unquote

def http_hello_page(request, response):
    username = ""
    
    # Read the request to extract username
    for line in request:
        line = line.strip()
        if not line:
            break
        
        # Look for username parameter in the request line
        if "username=" in line:
            match = re.search(r'username=([^&\\s]+)', line)
            if match:
                username = unquote(match.group(1))
    
    # Construct and write the response
    response.write("HTTP/1.1 200 OK\\n")
    response.write("Content-Type: text/html\\n")
    response.write("\\n")
    response.write("<html><body>\\n")
    response.write(f"<h1>hello {username}</h1>\\n")
    response.write("</body></html>\\n")
    response.flush()

def test_case(request_str, expected_user):
    print(f"Request: {request_str.replace(chr(10), ' ')}")
    
    request = StringIO(request_str)
    response = StringIO()
    
    http_hello_page(request, response)
    
    print(f"Response:\\n{response.getvalue()}")
    print("---")

if __name__ == "__main__":
    print("Testing HTTP Hello Page Function:\\n")
    
    # Test case 1
    test_case("GET /hello?username=John HTTP/1.1\\n", "John")
    
    # Test case 2
    test_case("GET /hello?username=Alice HTTP/1.1\\n", "Alice")
    
    # Test case 3
    test_case("GET /hello?username=Bob123 HTTP/1.1\\n", "Bob123")
    
    # Test case 4
    test_case("POST /hello HTTP/1.1\\nusername=Charlie\\n", "Charlie")
    
    # Test case 5
    test_case("GET /hello?username=Test%20User HTTP/1.1\\n", "Test User")
