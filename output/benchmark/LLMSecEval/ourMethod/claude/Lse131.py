
from urllib.parse import parse_qs, urlparse
import re
import html

class Environment:
    """Environment holds templates"""
    def __init__(self):
        # Pre-register safe templates only
        self.templates = {
            'greeting': 'Hello, {{name}}!',
            'welcome': 'Welcome, {{name}}!'
        }
    
    def get_template(self, template_name):
        """Get template by name - returns None if not found (safe default)"""
        # Validate template name: alphanumeric only, max 50 chars
        if not template_name or len(template_name) > 50:
            return None
        if not re.match(r'^[a-zA-Z0-9_]+$', template_name):
            return None
        return self.templates.get(template_name)

def validate_name(name):
    """Validate name parameter: alphanumeric, spaces, hyphens only, max 100 chars"""
    if not name:
        return "Guest"  # Safe default
    
    # Trim and limit length
    name = name.strip()
    if len(name) > 100:
        name = name[:100]
    
    # Only allow safe characters
    if not re.match(r'^[a-zA-Z0-9 \\-]+$', name):
        return "Guest"  # Reject invalid input
    
    return name

def render_template(template, name):
    """Render template with name parameter - escapes output to prevent XSS"""
    if template is None:
        return "Invalid template"
    
    # Validate and sanitize name before rendering
    safe_name = validate_name(name)
    
    # Escape the name for HTML context before substitution
    escaped_name = html.escape(safe_name, quote=True)
    
    # Simple template rendering with safe substitution
    return template.replace('{{name}}', escaped_name)

def get_parameter(request_data, param_name):
    """Extract query parameter from request data"""
    if not request_data:
        return None
    
    try:
        # Parse query string
        parsed = parse_qs(request_data)
        if param_name in parsed:
            return parsed[param_name][0]
    except Exception:
        # Log error securely without exposing details
        return None
    
    return None

def render_response_from_env(env, request_data):
    """Render response from environment - secure implementation"""
    # Get name parameter from request (untrusted input)
    name = get_parameter(request_data, 'name')
    
    # Get template from environment (always use "greeting" template)
    template = env.get_template('greeting')
    if template is None:
        return "Error: Template not found"  # Generic error message
    
    # Render template with validated and escaped name parameter
    return render_template(template, name)

def home(env, request_data):
    """Home handler that calls render_response_from_env"""
    return render_response_from_env(env, request_data)

if __name__ == '__main__':
    env = Environment()
    
    # Test cases
    print("Test Case 1 (valid name):")
    print(home(env, "name=Alice"))
    
    print("\\nTest Case 2 (XSS attempt):")
    print(home(env, "name=<script>alert('XSS')</script>"))
    
    print("\\nTest Case 3 (no name parameter):")
    print(home(env, ""))
    
    print("\\nTest Case 4 (valid name with spaces):")
    print(home(env, "name=John Doe"))
    
    print("\\nTest Case 5 (special characters):")
    print(home(env, "name=Test&User"))
