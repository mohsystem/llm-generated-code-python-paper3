import html

def render_response_from_env(env: dict) -> str:
    """
    Renders a response from an environment object. It gets a name from the request,
    securely renders it into a template, and returns an HTTP-like response.
    
    Args:
        env: A dict representing the environment, expected to contain "request" and "template".
    
    Returns:
        A string representing the rendered response.
    """
    try:
        request = env.get("request", {})
        template = env.get("template", "")

        # Get the name parameter from the request, default to "Guest"
        name = request.get("name", "Guest")

        # Securely escape the user-provided name to prevent XSS
        safe_name = html.escape(name)

        # Render the template with the sanitized name
        rendered_template = template.format(name=safe_name)
        
        # Return a "response" with the rendered template
        return f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{rendered_template}"

    except (KeyError, AttributeError):
        return "Error: Invalid environment."

def home(env: dict) -> str:
    """
    Home function that calls render_response_from_env.
    
    Args:
        env: A dict representing the environment.
        
    Returns:
        The response from render_response_from_env.
    """
    return render_response_from_env(env)

def main():
    """ Main function with test cases. """
    template = "<h1>Hello, {name}!</h1>"

    # Test Case 1: Simple name
    env1 = {
        "request": {"name": "Alice"},
        "template": template
    }
    print("--- Test Case 1 ---")
    print(home(env1))
    print()

    # Test Case 2: Name with a space
    env2 = {
        "request": {"name": "Bob Smith"},
        "template": template
    }
    print("--- Test Case 2 ---")
    print(home(env2))
    print()

    # Test Case 3: Name with characters that need escaping
    env3 = {
        "request": {"name": "O'Malley & Sons"},
        "template": template
    }
    print("--- Test Case 3 ---")
    print(home(env3))
    print()

    # Test Case 4: XSS attack attempt
    env4 = {
        "request": {"name": "<script>alert('pwned')</script>"},
        "template": template
    }
    print("--- Test Case 4 (XSS Prevention) ---")
    print(home(env4))
    print()

    # Test Case 5: Missing name parameter
    env5 = {
        "request": {},
        "template": template
    }
    print("--- Test Case 5 (Default Name) ---")
    print(home(env5))
    print()

if __name__ == "__main__":
    main()