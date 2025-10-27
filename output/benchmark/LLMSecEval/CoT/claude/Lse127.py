
import sys
from io import StringIO

MAX_USERNAME_LENGTH = 100

def sanitize_input(input_str):
    """Sanitize input to prevent injection attacks"""
    if not input_str:
        return ""
    
    html_escape_table = {
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    sanitized = []
    for char in input_str:
        if char in html_escape_table:
            sanitized.append(html_escape_table[char])
        elif 32 <= ord(char) <= 126:
            sanitized.append(char)
    
    return ''.join(sanitized)

def http_hello_page(request, response):
    """Process HTTP request and generate hello response"""
    try:
        username = request.readline().strip()
        
        # Input validation and sanitization
        if not username:
            username = "Guest"
        else:
            if len(username) > MAX_USERNAME_LENGTH:
                username = username[:MAX_USERNAME_LENGTH]
            username = sanitize_input(username)
        
        response_message = f"Hello {username}"
        response.write(response_message + "\\n")
        response.flush()
        
        return response_message
    except Exception as e:
        error_msg = "Error processing request"
        response.write(error_msg + "\\n")
        return error_msg

def main():
    test_cases = [
        "Alice",
        "Bob<script>alert('xss')</script>",
        "Charlie&Drop Table",
        "",
        "A" * 150
    ]
    
    for i, test_input in enumerate(test_cases, 1):
        request = StringIO(test_input + "\\n")
        response = StringIO()
        
        result = http_hello_page(request, response)
        print(f"Test {i}: {result}")

if __name__ == "__main__":
    main()
