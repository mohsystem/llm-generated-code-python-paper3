import html

def html_escape(text: str) -> str:
    """A wrapper around html.escape for clarity."""
    return html.escape(text)

def render_response_from_env(env: dict) -> str:
    """
    Renders a response from a template and request found in the environment.

    Args:
        env: A dictionary representing the environment, containing the request and template.
             Example: {'request': {'params': {'name': 'value'}}, 'template': 'Hello, {{name}}'}

    Returns:
        A string representing the rendered response body.
    """
    # Get the name parameter from the user request.
    # Use .get() for safe access, providing a default value.
    name = env.get('request', {}).get('params', {}).get('name', 'World')
    
    # Use default value if name is None or empty string
    if not name:
        name = "World"

    # Sanitize the input to prevent XSS attacks.
    sanitized_name = html_escape(name)
    
    # Get the template from the environment.
    template = env.get('template', '{{name}}')
    
    # Render the template with the sanitized name parameter.
    # The str.replace() method is safe from code execution vulnerabilities.
    rendered_template = template.replace('{{name}}', sanitized_name)
    
    # Return a response with the rendered template.
    return rendered_template

def home(env: dict) -> str:
    """
    Main handler that simulates a web request.

    Args:
        env: The environment for the request.

    Returns:
        The generated response string.
    """
    return render_response_from_env(env)

def main():
    """Main function with test cases."""
    template = "<h1>Hello, {{name}}!</h1>"
    
    test_cases = [
        # Test Case 1: Normal name
        {'name': 'Test Case 1 (Normal)', 'request': {'params': {'name': 'Alice'}}},
        # Test Case 2: XSS attack attempt
        {'name': 'Test Case 2 (XSS)', 'request': {'params': {'name': '<script>alert("xss")</script>'}}},
        # Test Case 3: Name with special HTML characters
        {'name': 'Test Case 3 (Special Chars)', 'request': {'params': {'name': 'Bob & "Charlie"'}}},
        # Test Case 4: Empty name parameter
        {'name': 'Test Case 4 (Empty Name)', 'request': {'params': {'name': ''}}},
        # Test Case 5: Missing name parameter
        {'name': 'Test Case 5 (Missing Name)', 'request': {'params': {}}},
    ]
    
    for test in test_cases:
        env = {
            'request': test['request'],
            'template': template
        }
        response = home(env)
        print(f"{test['name']}: {response}")

if __name__ == "__main__":
    main()