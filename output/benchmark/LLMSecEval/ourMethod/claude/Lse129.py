
from urllib.parse import parse_qs, urlparse
import html
import re

class Environment:
    """Template environment that stores templates"""
    def __init__(self):
        self.templates = {}
    
    def add_template(self, name, content):
        """Add a template to the environment"""
        if name is None or content is None:
            raise ValueError("Template name and content cannot be None")
        self.templates[name] = content
    
    def get_template(self, name):
        """Get a template by name"""
        return self.templates.get(name)


class Template:
    """Template class with safe rendering"""
    # Pattern to validate safe name input (alphanumeric, underscore, hyphen, space, max 100 chars)
    SAFE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\-\\s]{1,100}$')
    
    def __init__(self, content):
        self.content = content
    
    def render(self, name):
        """Render template with name parameter, escaping HTML to prevent XSS"""
        # Validate name parameter - reject if None or doesn't match safe pattern
        if name is None or not self.SAFE_NAME_PATTERN.match(name):
            # Fail closed: use a safe default instead of user input
            name = "Guest"
        
        # Escape HTML special characters to prevent XSS
        safe_name = html.escape(name, quote=True)
        
        # Simple template variable replacement
        return self.content.replace("{{name}}", safe_name)


class Response:
    """Response class to encapsulate HTTP response"""
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code


def get_query_parameter(request_uri, param_name):
    """Extract query parameter safely from URI"""
    if not request_uri or not param_name:
        return None
    
    try:
        # Parse URI safely
        parsed = urlparse(request_uri)
        query_params = parse_qs(parsed.query)
        
        # Get parameter value (parse_qs returns list)
        values = query_params.get(param_name, [])
        if values and len(values) > 0:
            value = values[0]
            # Limit parameter length to prevent DoS
            if len(value) > 1000:
                return None
            return value
    except Exception:
        # Invalid URI or parsing error - return None
        return None
    
    return None


def render_response_from_env(env, request_uri):
    """Render response from environment with security controls"""
    if env is None or request_uri is None:
        return Response("Bad Request", 400)
    
    # Get name parameter from request with input validation
    name = get_query_parameter(request_uri, "name")
    
    # Get template from environment - use a fixed template name to prevent template injection
    template_content = env.get_template("greeting")
    if template_content is None:
        return Response("Template not found", 500)
    
    # Create template and render with validated name
    template = Template(template_content)
    rendered = template.render(name)
    
    # Return response with rendered content
    return Response(rendered, 200)


def home(env, request_uri):
    """Home function that calls render_response_from_env"""
    # Delegate to render_response_from_env
    return render_response_from_env(env, request_uri)


# Test cases
if __name__ == "__main__":
    env = Environment()
    env.add_template("greeting", "<html><body>Hello, {{name}}!</body></html>")
    
    print("Test Case 1: Valid name parameter")
    resp1 = home(env, "http://localhost/?name=Alice")
    print(f"Status: {resp1.status_code}")
    print(f"Body: {resp1.body}")
    print()
    
    print("Test Case 2: Name with spaces")
    resp2 = home(env, "http://localhost/?name=John%20Doe")
    print(f"Status: {resp2.status_code}")
    print(f"Body: {resp2.body}")
    print()
    
    print("Test Case 3: XSS attempt (should be escaped)")
    resp3 = home(env, "http://localhost/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    print(f"Status: {resp3.status_code}")
    print(f"Body: {resp3.body}")
    print()
    
    print("Test Case 4: No name parameter (should use default)")
    resp4 = home(env, "http://localhost/")
    print(f"Status: {resp4.status_code}")
    print(f"Body: {resp4.body}")
    print()
    
    print("Test Case 5: Invalid characters (should use default)")
    resp5 = home(env, "http://localhost/?name=%00%01%02")
    print(f"Status: {resp5.status_code}")
    print(f"Body: {resp5.body}")
