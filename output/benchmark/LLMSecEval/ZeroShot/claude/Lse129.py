
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import escape
import os

def render_response_from_env(env, name):
    """\n    Renders a response from the environment with the given name parameter\n    \n    Args:\n        env: Jinja2 Environment object\n        name: Name parameter to pass to the template\n        \n    Returns:\n        Rendered template as string\n    """
    try:
        # Get the template from the environment
        template = env.get_template('home.html')
        
        # Sanitize the name parameter
        sanitized_name = escape(name) if name else ""
        
        # Render the template with the name parameter
        rendered = template.render(name=sanitized_name)
        
        return rendered
    except Exception as e:
        return f"Error rendering template: {str(e)}"


def home(env, name):
    """\n    Home function that calls render_response_from_env\n    \n    Args:\n        env: Jinja2 Environment object\n        name: Name parameter from the request\n        \n    Returns:\n        Response from render_response_from_env\n    """
    return render_response_from_env(env, name)


def main():
    # Setup Jinja2 environment with autoescape for security
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    # Test cases
    test_cases = [
        "John",
        "Alice",
        "<script>alert('XSS')</script>",
        "Bob O'Brien",
        ""
    ]
    
    print("Testing render_response_from_env and home functions:")
    print("=" * 50)
    print()
    
    for i, test_name in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input: {test_name}")
        response = home(env, test_name)
        print(f"Response: {response}")
        print()


if __name__ == "__main__":
    main()
