import html

def generate_web_page(user_input: str) -> str:
    """
    Generates a simple HTML page string displaying user-supplied input securely.
    It uses html.escape() to prevent Cross-Site Scripting (XSS).

    Args:
        user_input: The user-supplied string.

    Returns:
        A string containing the full HTML page.
    """
    # Sanitize the user input to prevent XSS
    escaped_input = html.escape(user_input)

    # Embed the sanitized input into an HTML template
    web_page_content = f"""<!DOCTYPE html>
<html>
<head>
  <title>User Input</title>
</head>
<body>
  <h1>User Comment:</h1>
  <p>{escaped_input}</p>
</body>
</html>"""
    return web_page_content

def main():
    """ Main function with test cases """
    test_cases = [
        "Hello, World!",
        "1 < 5",
        "This is a 'quote' & an \"ampersand\"",
        "<script>alert('XSS Attack!')</script>",
        ""
    ]
    
    print("--- Python Test Cases ---")
    for i, test_input in enumerate(test_cases):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Input: {test_input}")
        web_page = generate_web_page(test_input)
        print(f"Generated HTML:\n{web_page}")

if __name__ == "__main__":
    main()