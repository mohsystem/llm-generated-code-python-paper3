
import html

def escape_html(input_str):
    """HTML escape function to prevent XSS attacks"""
    if input_str is None:
        return ""
    return html.escape(input_str, quote=True)

def display_user_input(user_input):
    """Display user input safely on a web page"""
    sanitized_input = escape_html(user_input)
    html_output = f"""<!DOCTYPE html>\n<html>\n<head>\n    <meta charset="UTF-8">\n    <title>User Input Display</title>\n</head>\n<body>\n    <h1>User Input Display</h1>\n    <p>You entered: {sanitized_input}</p>\n</body>\n</html>"""
    return html_output

def main():
    print("=== Test Case 1: Normal Text ===")
    test1 = "Hello, World!"
    print(display_user_input(test1))
    print()
    
    print("=== Test Case 2: XSS Attack Attempt (Script Tag) ===")
    test2 = "<script>alert('XSS')</script>"
    print(display_user_input(test2))
    print()
    
    print("=== Test Case 3: Special Characters ===")
    test3 = "Price: $100 & Free Shipping!"
    print(display_user_input(test3))
    print()
    
    print("=== Test Case 4: HTML Injection Attempt ===")
    test4 = "<img src=x onerror=alert('XSS')>"
    print(display_user_input(test4))
    print()
    
    print("=== Test Case 5: Mixed Content ===")
    test5 = "My email: user@example.com & phone: 555-1234"
    print(display_user_input(test5))

if __name__ == "__main__":
    main()
