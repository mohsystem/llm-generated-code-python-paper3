# The jinja2 library is required for this code.
# You can install it using: pip install Jinja2
import jinja2
import html

def render_response_from_env(env, name):
    """
    Renders a response from a Jinja2 template environment.
    This function simulates getting a 'name' parameter from a user request.
    Jinja2's default auto-escaping provides protection against XSS.

    :param env: The Jinja2 Environment object.
    :param name: The name parameter from the user request.
    :return: A response string with the rendered template.
    """
    try:
        # Get the template from the environment.
        template = env.get_template('template.html')
        
        # Render the template with the name parameter.
        # Jinja2 automatically escapes the 'name' variable by default.
        rendered_template = template.render(name=name)
        
        # Return a response with the rendered template.
        return rendered_template
    except jinja2.TemplateError as e:
        return f"Error rendering template: {e}"

def home(name):
    """
    Simulates a "home" endpoint/controller function.
    It calls the render_response_from_env function with a pre-configured env.

    :param name: The name parameter from the user request.
    :return: The response from the render_response_from_env function.
    """
    # Create a Jinja2 environment. The loader points to a dictionary of templates.
    # autoescape=True is the default and is crucial for security.
    env = jinja2.Environment(
        loader=jinja2.DictLoader({'template.html': '<h1>Hello, {{ name }}!</h1>'}),
        autoescape=jinja2.select_autoescape(['html', 'xml'])
    )
    
    response = render_response_from_env(env, name)
    return response

# Main execution block with test cases
if __name__ == "__main__":
    test_names = [
        "World",  # Test Case 1: Normal input
        "<script>alert('XSS');</script>",  # Test Case 2: Malicious script input
        "",  # Test Case 3: Empty input
        "John \"Johnny\" Doe & Sons' Store",  # Test Case 4: Input with special characters
        "A very long name with multiple spaces and characters to test rendering"  # Test Case 5: Long input
    ]
    
    print("--- Python Test Cases ---")
    for i, name_input in enumerate(test_names, 1):
        print(f'Test Case {i} (Input: "{name_input}"):')
        response = home(name_input)
        print(f"Output: {response}\n")