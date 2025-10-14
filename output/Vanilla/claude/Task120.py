
import html

class Task120:
    @staticmethod
    def sanitize_html(input_text):
        """Sanitize HTML to prevent XSS attacks"""
        if input_text is None:
            return ""
        return html.escape(input_text)
    
    @staticmethod
    def generate_web_page(user_input):
        """Generate HTML page with user input"""
        sanitized_input = Task120.sanitize_html(user_input)
        
        html_content = f"""<!DOCTYPE html>\n<html>\n<head>\n    <title>User Input Display</title>\n    <style>\n        body {{ font-family: Arial, sans-serif; margin: 40px; }}\n        .container {{ border: 2px solid #333; padding: 20px; border-radius: 5px; }}\n        h1 {{ color: #333; }}\n    </style>\n</head>\n<body>\n    <div class="container">\n        <h1>User Input Display</h1>\n        <p><strong>You entered:</strong></p>\n        <p>{sanitized_input}</p>\n    </div>\n</body>\n</html>"""
        
        return html_content

def main():
    print("Test Case 1: Simple text")
    print(Task120.generate_web_page("Hello, World!"))
    print("\\n" + "="*80 + "\\n")
    
    print("Test Case 2: Text with HTML tags (XSS prevention)")
    print(Task120.generate_web_page("<script>alert('XSS')</script>"))
    print("\\n" + "="*80 + "\\n")
    
    print("Test Case 3: Text with special characters")
    print(Task120.generate_web_page("Price: $100 & up, 50% off!"))
    print("\\n" + "="*80 + "\\n")
    
    print("Test Case 4: Multi-line text")
    print(Task120.generate_web_page("Line 1\\nLine 2\\nLine 3"))
    print("\\n" + "="*80 + "\\n")
    
    print("Test Case 5: Empty input")
    print(Task120.generate_web_page(""))
    print("\\n" + "="*80 + "\\n")

if __name__ == "__main__":
    main()
