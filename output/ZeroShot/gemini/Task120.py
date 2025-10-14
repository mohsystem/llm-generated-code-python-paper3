import html

def generate_safe_html(user_input: str) -> str:
    """
    Sanitizes user input by escaping HTML special characters to prevent XSS attacks,
    and then embeds it into a simple HTML page structure.

    :param user_input: The raw string provided by the user.
    :return: A string containing a full HTML document with the sanitized user input.
    """
    if user_input is None:
        user_input = ""
        
    # html.escape handles characters like &, <, >, ", '
    sanitized_input = html.escape(user_input)
    
    return f"<html><body><p>User input: {sanitized_input}</p></body></html>"

if __name__ == "__main__":
    test_cases = [
        "Hello, World!",
        "1 < 5 is true",
        "He said, \"It's a & b > c\"",
        "<script>alert('XSS attack!');</script>",
        ""
    ]

    print("--- Python Test Cases ---")
    for test_case in test_cases:
        print(f"Input: {test_case}")
        safe_html = generate_safe_html(test_case)
        print(f"Output: {safe_html}")
        print()