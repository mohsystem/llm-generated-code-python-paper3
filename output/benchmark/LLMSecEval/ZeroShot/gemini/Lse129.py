import html

def render_response_from_env(env, request_params):
    """
    Renders a template from an environment with a given name parameter from a request.
    
    Args:
        env (dict): A dictionary representing the environment, containing the template.
        request_params (dict): A dictionary representing request parameters, containing the name.
        
    Returns:
        str: A string representing the rendered response.
    """
    name = request_params.get("name", "")
    template = env.get("template", "")
    
    # Secure: Escape the user-provided name to prevent Cross-Site Scripting (XSS).
    escaped_name = html.escape(name)
    
    # Render the template by replacing the placeholder with the escaped name.
    rendered_template = template.replace("{{ name }}", escaped_name)
    
    return rendered_template

def home(env, request_params):
    """
    Simulates a home route handler that renders a response.
    
    Args:
        env (dict): The environment dictionary.
        request_params (dict): The request parameters dictionary.
        
    Returns:
        str: The response from the renderer.
    """
    return render_response_from_env(env, request_params)

if __name__ == "__main__":
    # 1. Setup the environment with a template.
    env = {"template": "<h1>Hello, {{ name }}!</h1>"}

    # 2. Define test cases.
    test_cases = [
        # Test case 1: Normal name
        {"name": "World"},
        # Test case 2: Name with spaces
        {"name": "Jane Doe"},
        # Test case 3: Empty name
        {"name": ""},
        # Test case 4: Malicious script (XSS attempt)
        {"name": "<script>alert('XSS')</script>"},
        # Test case 5: Name with HTML characters
        {"name": "<b>Bold</b>"}
    ]

    # 3. Run test cases.
    for i, request in enumerate(test_cases, 1):
        response = home(env, request)
        print(f"Test Case {i} (name={request.get('name')}):")
        print(f"Output: {response}\n")