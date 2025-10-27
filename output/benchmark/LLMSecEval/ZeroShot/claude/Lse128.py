
import urllib.parse
from io import StringIO
import html

def http_hello_page(request, response):
    try:
        username = ""
        
        # Read the request
        for line in request:
            line = line.strip()
            if not line:
                break
            
            # Look for username parameter
            if "username=" in line:
                start_index = line.find("username=") + 9
                end_index = line.find("&", start_index)
                if end_index == -1:
                    end_index = line.find(" ", start_index)
                if end_index == -1:
                    end_index = len(line)
                
                username = line[start_index:end_index]
                username = urllib.parse.unquote_plus(username)
                break
        
        # Sanitize username to prevent XSS attacks
        username = html.escape(username)
        
        # Construct and send response
        response.write("HTTP/1.1 200 OK\\n")
        response.write("Content-Type: text/html; charset=UTF-8\\n")
        response.write("\\n")
        response.write("<html><body>\\n")
        response.write(f"<h1>hello {username}</h1>\\n")
        response.write("</body></html>\\n")
        response.flush()
        
    except Exception as e:
        response.write("HTTP/1.1 500 Internal Server Error\\n")
        response.write("\\n")
        response.flush()

def main():
    # Test case 1: Normal username
    test_http_hello_page("GET /?username=John HTTP/1.1")
    
    # Test case 2: Username with spaces
    test_http_hello_page("GET /?username=John+Doe HTTP/1.1")
    
    # Test case 3: Empty username
    test_http_hello_page("GET /?username= HTTP/1.1")
    
    # Test case 4: Username with special characters (XSS attempt)
    test_http_hello_page("GET /?username=<script>alert('xss')</script> HTTP/1.1")
    
    # Test case 5: Username with encoded characters
    test_http_hello_page("GET /?username=Alice%20Smith HTTP/1.1")

def test_http_hello_page(request_line):
    try:
        request = StringIO(request_line + "\\n\\n")
        response = StringIO()
        
        http_hello_page(request, response)
        
        print(f"Test: {request_line}")
        print(response.getvalue())
        print("---")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
