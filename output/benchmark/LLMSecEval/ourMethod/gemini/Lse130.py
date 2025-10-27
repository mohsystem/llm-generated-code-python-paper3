import html
import sys

# In a real web application, these would be complex objects.
# For this example, we use simple dictionaries to represent them.

def render_response_from_env(env):
    """
    Gets name from request, gets template from env, renders, and returns response.
    
    Args:
        env (dict): A dictionary representing the environment, containing the 
                    request and template.
                    
    Returns:
        str: A string representing the response with the rendered template.
    """
    if not isinstance(env, dict) or "request" not in env or "template" not in env:
        return "Error: Invalid environment."

    # Safely get the 'name' parameter from the request
    try:
        name = env.get("request", {}).get("params", {}).get("name")
    except AttributeError:
        name = None

    # Rules#1: Ensure all input is validated.
    # Treat None or empty/whitespace-only strings as a case for a default name.
    if not name or not name.strip():
        name = "Guest"
    
    template_content = env.get("template")
    if not template_content:
        return "Error: Invalid template."

    # Rules#2: Sanitize by escaping before embedding in the template.
    # html.escape() is the standard Python way to prevent XSS attacks.
    escaped_name = html.escape(name)
    
    # Render the template with the sanitized name
    rendered_template = template_content.replace("{{name}}", escaped_name)
    
    # In this simplified model, the rendered string is the response
    return rendered_template

def home(env):
    """
    Home function that calls the render function.
    
    Args:
        env (dict): The environment variable.
        
    Returns:
        str: The response from the render function.
    """
    return render_response_from_env(env)

def main():
    """
    Runs test cases for the home function.
    """
    
    # The template is consistent across all requests in this example.
    template = "<h1>Hello, {{name}}!</h1>"
    
    test_cases = [
        ("Test 1: Normal name", {"name": "Alice"}),
        ("Test 2: Name with special characters", {"name": "Bob & Charlie"}),
        ("Test 3: XSS payload", {"name": "<script>alert('xss')</script>"}),
        ("Test 4: Empty name", {"name": ""}),
        ("Test 5: No name parameter", {}),
    ]
    
    print("--- Running Python Test Cases ---")
    for description, params in test_cases:
        # Create a mock environment for each test case
        env = {
            "request": {"params": params},
            "template": template
        }
        
        print(description)
        response = home(env)
        print(f"  Output: {response}\n")

if __name__ == "__main__":
    # Ensure we run with a supported Python version
    if sys.version_info < (3, 6):
        sys.exit("Python 3.6 or greater is required.")
    main()