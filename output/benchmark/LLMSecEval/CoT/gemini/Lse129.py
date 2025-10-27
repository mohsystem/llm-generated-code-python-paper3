import html

# Note: In Python, it's not conventional to wrap standalone functions in a class
# unless they are part of a larger object-oriented design. The functions are
# provided at the module level as is standard practice.

def render_response_from_env(env):
    """
    Renders a template from an environment with a name parameter.
    This simulates a web framework's template rendering.
    
    Args:
        env (dict): A dictionary representing the environment, expected to contain 
                    a "template" and a "request" which in turn contains "params" 
                    with a "name".

    Returns:
        str: A response string with the rendered template.
    """
    # Safely get the nested name parameter, default to "Guest"
    name = env.get("request", {}).get("params", {}).get("name")
    if not name or not name.strip():
        name = "Guest"

    # Get the template from the environment
    template = env.get("template", "<h1>Hello, {{ name }}!</h1>")
    
    # SECURITY: Escape the user-provided name to prevent XSS attacks
    safe_name = html.escape(name)

    # Render the template by replacing the placeholder
    rendered_template = template.replace("{{ name }}", safe_name)
    
    # Return a response with the rendered template
    # In a real web app, this would be an HTTP Response object
    return rendered_template

def home(env):
    """
    Simulates a "home" endpoint controller.
    
    Args:
        env (dict): The environment for the request.
        
    Returns:
        str: The response generated from the environment.
    """
    return render_response_from_env(env)


class Lse129:
    """
    A wrapper class to meet the requirement of having a main class named Lse129.
    The core logic is in the standalone functions above.
    """
    @staticmethod
    def run_tests():
        # --- Test Cases ---
        template = "<h1>Hello, {{ name }}!</h1>"

        # Test Case 1: Normal name
        env1 = {
            "request": {"params": {"name": "Alice"}},
            "template": template
        }
        print(f"Test Case 1 (Normal): {home(env1)}")

        # Test Case 2: XSS attack attempt
        env2 = {
            "request": {"params": {"name": "<script>alert('XSS')</script>"}},
            "template": template
        }
        print(f"Test Case 2 (XSS): {home(env2)}")

        # Test Case 3: Empty name parameter
        env3 = {
            "request": {"params": {"name": ""}},
            "template": template
        }
        print(f"Test Case 3 (Empty): {home(env3)}")

        # Test Case 4: None (null) name parameter
        env4 = {
            "request": {"params": {"name": None}},
            "template": template
        }
        print(f"Test Case 4 (None): {home(env4)}")

        # Test Case 5: Missing 'name' key in params
        env5 = {
            "request": {"params": {}},
            "template": template
        }
        print(f"Test Case 5 (Missing): {home(env5)}")


if __name__ == "__main__":
    Lse129.run_tests()