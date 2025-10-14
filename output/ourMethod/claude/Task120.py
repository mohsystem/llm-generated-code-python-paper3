
from html import escape
from typing import Optional
import sys


def sanitize_input(user_input: Optional[str]) -> str:
    """\n    Sanitize user input to prevent XSS attacks.\n    Validates length and escapes HTML special characters.\n    """
    if user_input is None:
        return ""
    
    if len(user_input) > 1000:
        user_input = user_input[:1000]
    
    sanitized = escape(user_input, quote=True)
    
    return sanitized


def generate_html_page(user_input: str) -> str:
    """\n    Generate a complete HTML page with sanitized user input.\n    Includes security headers via meta tags.\n    """
    sanitized = sanitize_input(user_input)
    
    html = f"""<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<meta http-equiv="X-Content-Type-Options" content="nosniff">\n<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">\n<title>User Input Display</title>\n<style>body{{font-family:Arial,sans-serif;margin:20px;}}</style>\n</head>\n<body>\n<h1>User Input Display</h1>\n<div id="user-content">\n<p>Your input:</p>\n<pre>{sanitized}</pre>\n</div>\n</body>\n</html>"""
    
    return html


def main() -> None:
    """Test the input sanitization and HTML generation."""
    print("Test Case 1: Simple text")
    test1 = generate_html_page("Hello World")
    print("Hello World" in test1)
    
    print("\\nTest Case 2: XSS attempt with script tag")
    test2 = generate_html_page("<script>alert('XSS')</script>")
    print("&lt;script&gt;" in test2)
    print("<script>alert" not in test2)
    
    print("\\nTest Case 3: HTML injection attempt")
    test3 = generate_html_page("<img src=x onerror=alert(1)>")
    print("&lt;img" in test3)
    print("<img src=" not in test3)
    
    print("\\nTest Case 4: Special characters")
    test4 = generate_html_page("Test & \"quotes\" and 'apostrophes'")
    print("&amp;" in test4)
    print("&quot;" in test4)
    print("&#x27;" in test4)
    
    print("\\nTest Case 5: Empty input")
    test5 = generate_html_page("")
    print("<pre></pre>" in test5)


if __name__ == "__main__":
    main()
