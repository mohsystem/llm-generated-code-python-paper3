import html

class Environment:
    """Simulates an environment that holds templates."""
    def __init__(self, template):
        self.template = template

    def get_template(self):
        return self.template

def render_response_from_env(env, request):
    """
    Renders a response from a template in the environment using parameters from a request.
    
    Args:
        env (Environment): The environment containing the template.
        request (dict): A dictionary simulating a user request with parameters.
    
    Returns:
        str: A string representing the response with the rendered template.
    """
    # 1. Get the name parameter from the user request.
    # Default to 'Guest' if not provided.
    name = request.get("name", "Guest")
    
    # In a real web application, user input must be sanitized/escaped to prevent XSS.
    # Here, we use html.escape as a demonstration of good practice.
    safe_name = html.escape(name)

    # 2. Get the template from the environment.
    template = env.get_template()

    # 3. Render the template with the name parameter from the request.
    rendered_template = template.replace("{{name}}", safe_name)

    # 4. Return a response with the rendered template.
    return rendered_template

def home(env, request):
    """
    Simulates a home route handler.
    
    Args:
        env (Environment): The environment object.
        request (dict): The request dictionary.
        
    Returns:
        str: The response from the rendering function.
    """
    response = render_response_from_env(env, request)
    return response

# Main execution block with 5 test cases
if __name__ == "__main__":
    # Setup a shared environment for all requests
    env = Environment("Hello, {{name}}! Welcome to our site.")

    # --- Test Cases ---

    # Test Case 1: Standard name
    request1 = {"name": "Alice"}
    response1 = home(env, request1)
    print(f"Test Case 1: {response1}")

    # Test Case 2: Another name
    request2 = {"name": "Bob"}
    response2 = home(env, request2)
    print(f"Test Case 2: {response2}")
    
    # Test Case 3: Name with numbers
    request3 = {"name": "Charlie7"}
    response3 = home(env, request3)
    print(f"Test Case 3: {response3}")

    # Test Case 4: No "name" parameter provided (defaults to "Guest")
    request4 = {}
    response4 = home(env, request4)
    print(f"Test Case 4: {response4}")

    # Test Case 5: Name that could be an XSS attempt in a real web app
    request5 = {"name": "<script>alert('xss')</script>"}
    response5 = home(env, request5)
    print(f"Test Case 5: {response5}")