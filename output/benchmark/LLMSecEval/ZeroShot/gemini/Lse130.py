from flask import Flask, request, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

# In a real Flask app, you'd load templates from files.
# For this self-contained example, we'll simulate it with a string.
# Jinja2 is secure by default and auto-escapes variables.
env = Environment(autoescape=select_autoescape(['html', 'xml']))
template_str = "<html><body><h1>Hello, {{ name }}!</h1></body></html>"
template = env.from_string(template_str)

def render_response_from_env(environment):
    """
    Renders a response based on the request environment.

    Args:
        environment: The request object from Flask.

    Returns:
        A Flask Response object with the rendered template.
    """
    # Get the name parameter from the request.
    # The 'environment' in this context is the Flask request object.
    name = environment.args.get('name', 'World')

    # The template is already available in the global scope `env`.
    # Jinja2's render function automatically escapes the 'name' variable,
    # preventing XSS attacks.
    rendered_template = template.render(name=name)

    # Return a response with the rendered template.
    return Response(rendered_template, mimetype='text/html')

app = Flask(__name__)

@app.route('/')
def home():
    """
    Calls the render function with the current request environment.
    """
    # The `request` object from Flask serves as the `env` variable.
    return render_response_from_env(request)

if __name__ == '__main__':
    # The main method provides test cases as URLs to visit.
    # To run, execute `python your_script_name.py` and open the URLs in a browser.
    print("Server starting on http://127.0.0.1:5000")
    print("--- Test Cases ---")
    print("1. Normal case: Open http://127.0.0.1:5000/?name=Alice")
    print("2. Default case: Open http://127.0.0.1:5000/")
    print("3. Empty param: Open http://127.0.0.1:5000/?name=")
    print("4. Special chars: Open http://127.0.0.1:5000/?name=Bob%20&%20Charlie")
    print("5. XSS attack test (should be safely escaped): Open http://127.0.0.1:5000/?name=%3Cscript%3Ealert('XSS')%3C/script%3E")
    
    # Note: Do not use `app.run(debug=True)` in a production environment.
    app.run(host='127.0.0.1', port=5000)