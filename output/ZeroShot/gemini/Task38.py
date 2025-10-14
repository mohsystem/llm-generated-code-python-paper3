import html

def secure_display(user_input: str) -> str:
    """
    Securely escapes a user input string to prevent XSS attacks 
    and wraps it in a basic HTML structure.
    
    :param user_input: The raw string from the user.
    :return: A string containing an HTML page with the sanitized input.
    """
    if user_input is None:
        user_input = ""
    # The html.escape() function handles '&', '<', '>', '"', "'"
    sanitized_input = html.escape(user_input)
    return f"<html><body><h1>User Input:</h1><p>{sanitized_input}</p></body></html>"

def main():
    """Main function with 5 test cases."""
    test_cases = [
        "Hello, World!",  # Normal input
        "<script>alert('XSS');</script>",  # Malicious script
        "John & Doe > Company",  # Input with special HTML characters
        "This is a \"quote\".",  # Input with quotes
        "1 < 2 && 3 > 1"  # Another input with special characters
    ]

    print("--- Running Python Test Cases ---")
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest Case {i}:")
        print(f"Original Input: {test_case}")
        safe_html = secure_display(test_case)
        print(f"Generated Safe HTML: {safe_html}")

if __name__ == "__main__":
    main()