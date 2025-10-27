import html

def render_response_from_env(env, request):
    """
    Renders a response from a template and request data.

    Args:
        env (dict): A dictionary representing the environment, containing templates.
        request (dict): A dictionary representing the incoming request parameters.

    Returns:
        str: A string representing the rendered response.
    """
    # Get the template from the environment
    template = env.get("template")
    if not template:
        return "Error: Template not found."

    # Get the name parameter from the request, with a default value
    name = request.get("name", "Guest")

    # Sanitize input to prevent XSS by escaping HTML special characters.
    # This is a critical security step.
    sanitized_name = html.escape(name)

    # Render the template with the sanitized parameter
    rendered_template = template.replace("{{name}}", sanitized_name)
    
    return rendered_template

def home(env, request):
    """
    A home function that simulates a controller action.
    It calls render_response_from_env and returns its result.
    
    Args:
        env (dict): A dictionary representing the environment.
        request (dict): A dictionary representing the request.

    Returns:
        str: The response from the renderer.
    """
    return render_response_from_env(env, request)

def main():
    """Main function with test cases."""
    # Setup a mock environment with a template
    env = {"template": "<h1>Hello, {{name}}!</h1>"}

    print("--- 5 Test Cases ---")

    # Test Case 1: Normal name
    request1 = {"name": "Alice"}
    print(f"Test 1 (Normal): {home(env, request1)}")

    # Test Case 2: Name with HTML characters (potential XSS)
    request2 = {"name": "<script>alert('xss')</script>"}
    print(f"Test 2 (XSS): {home(env, request2)}")

    # Test Case 3: Empty name parameter
    request3 = {"name": ""}
    print(f"Test 3 (Empty): {home(env, request3)}")

    # Test Case 4: Missing name parameter
    request4 = {}
    print(f"Test 4 (Missing): {home(env, request4)}")

    # Test Case 5: Name with other special characters
    request5 = {"name": "Bob & Charlie's \"Shop\""}
    print(f"Test 5 (Special Chars): {home(env, request5)}")


if __name__ == "__main__":
    main()