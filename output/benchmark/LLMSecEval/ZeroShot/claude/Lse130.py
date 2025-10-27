
from html import escape
from urllib.parse import parse_qs, unquote

class Environment:
    def __init__(self):
        self.templates = {
            'default': '<html><body><h1>Hello, {{name}}!</h1></body></html>'
        }
    
    def get_template(self, template_name='default'):
        return self.templates.get(template_name, self.templates['default'])

class Response:
    def __init__(self, content, status_code=200):
        self.content = content
        self.status_code = status_code
    
    def get_content(self):
        return self.content
    
    def get_status_code(self):
        return self.status_code

def sanitize_input(input_str):
    """Sanitize input to prevent XSS attacks"""
    if input_str is None:
        return ""
    return escape(input_str)

def render_response_from_env(env, params):
    """Render response from environment with request parameters"""
    # Get name parameter from request (sanitize to prevent XSS)
    name = params.get('name', 'Guest')
    name = sanitize_input(name)
    
    # Get template from environment
    template = env.get_template('default')
    
    # Render template with name parameter
    rendered_content = template.replace('{{name}}', name)
    
    # Return response with rendered template
    return Response(rendered_content, 200)

def home(env, params):
    """Home function that calls render_response_from_env"""
    return render_response_from_env(env, params)

class Lse130:
    @staticmethod
    def main():
        env = Environment()
        
        # Test case 1: Normal name
        params1 = {'name': 'John'}
        response1 = home(env, params1)
        print(f"Test 1: {response1.get_content()}")
        
        # Test case 2: Empty name (should default to Guest)
        params2 = {}
        response2 = home(env, params2)
        print(f"Test 2: {response2.get_content()}")
        
        # Test case 3: Name with special characters (XSS attempt)
        params3 = {'name': "<script>alert('XSS')</script>"}
        response3 = home(env, params3)
        print(f"Test 3: {response3.get_content()}")
        
        # Test case 4: Name with quotes
        params4 = {'name': 'John "Doe"'}
        response4 = home(env, params4)
        print(f"Test 4: {response4.get_content()}")
        
        # Test case 5: Unicode name
        params5 = {'name': 'José'}
        response5 = home(env, params5)
        print(f"Test 5: {response5.get_content()}")

if __name__ == '__main__':
    Lse130.main()
