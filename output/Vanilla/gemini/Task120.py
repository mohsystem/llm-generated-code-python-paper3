def create_web_page(content, filename):
    """
    Creates an HTML file that displays the given content.

    :param content: The user-supplied string to display on the web page.
    :param filename: The name of the HTML file to create.
    """
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Input Display</title>
</head>
<body>
    <h1>User-Supplied Content:</h1>
    <p>{content}</p>
</body>
</html>"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Successfully created {filename}")
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")

def main():
    """Main function with 5 test cases."""
    create_web_page("Hello, World!", "python_test1.html")
    create_web_page("This is a test from Python.", "python_test2.html")
    create_web_page("12345", "python_test3.html")
    create_web_page("Special characters: <script>alert('xss')</script>", "python_test4.html")
    create_web_page("A longer sentence to see how it wraps inside the paragraph tag on the web page.", "python_test5.html")

if __name__ == "__main__":
    main()