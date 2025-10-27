
import re
import html
from typing import Dict, Optional

# Response class to hold rendered content
class Response:
    def __init__(self, content: str, status_code: int = 200):
        self.content = content if content is not None else ""
        self.status_code = status_code
    
    def get_content(self) -> str:
        return self.content
    
    def get_status_code(self) -> int:
        return self.status_code

# Request class to hold parameters
class Request:
    def __init__(self, params: Optional[Dict[str, str]] = None):
        self.params = params if params is not None else {}
    
    def get_parameter(self, key: str) -> Optional[str]:
        if key is None:
            return None
        value = self.params.get(key)
        # Limit input length to prevent DoS
        if value is not None and len(value) > 1000:
            value = value[:1000]
        return value

# Environment class holding request and template
class Environment:
    def __init__(self, request: Request, template: str):
        self.request = request
        # Validate template size
        if template is not None and len(template) > 100000:
            raise ValueError("Template size exceeds maximum limit")
        self.template = template if template is not None else ""
    
    def get_request(self) -> Request:
        return self.request
    
    def get_template(self) -> str:
        return self.template

# Template engine with XSS protection
class TemplateEngine:
    @staticmethod
    def render(template: str, context: Dict[str, str]) -> str:
        if template is None or context is None:
            return ""
        # Get name from context and escape HTML to prevent XSS
        name = context.get("name", "")
        safe_name = html.escape(name, quote=True)
        # Replace template variable with escaped value
        result = re.sub(r'\\{\\{\\s*name\\s*\\}\\}', safe_name, template)
        return result

# Renders response from environment
# Security: Validates all inputs, escapes output to prevent XSS
def render_response_from_env(env: Optional[Environment]) -> Response:
    if env is None:
        return Response("Invalid environment", 400)
    
    try:
        # Get request - treat all input as untrusted
        request = env.get_request()
        if request is None:
            return Response("Invalid request", 400)
        
        # Get name parameter from request
        name = request.get_parameter("name")
        if name is None:
            name = ""
        
        # Get template from environment
        template = env.get_template()
        if not template:
            return Response("Template not found", 404)
        
        # Render template with sanitized context
        context = {"name": name}
        rendered = TemplateEngine.render(template, context)
        
        return Response(rendered, 200)
        
    except Exception as e:
        # Log error internally, return generic message
        print(f"Error rendering template: {str(e)}", file=__import__('sys').stderr)
        return Response("Internal server error", 500)

# Home function that calls render_response_from_env
def home(env: Optional[Environment]) -> Response:
    return render_response_from_env(env)

# Test cases
if __name__ == "__main__":
    # Test 1: Normal input
    params1 = {"name": "John"}
    req1 = Request(params1)
    env1 = Environment(req1, "Hello, {{ name }}!")
    resp1 = home(env1)
    print(f"Test 1: {resp1.get_content()} (Status: {resp1.get_status_code()})")
    
    # Test 2: XSS attempt - should be escaped
    params2 = {"name": "<script>alert('XSS')</script>"}
    req2 = Request(params2)
    env2 = Environment(req2, "Hello, {{ name }}!")
    resp2 = home(env2)
    print(f"Test 2: {resp2.get_content()} (Status: {resp2.get_status_code()})")
    
    # Test 3: Empty name parameter
    params3 = {"name": ""}
    req3 = Request(params3)
    env3 = Environment(req3, "Hello, {{ name }}!")
    resp3 = home(env3)
    print(f"Test 3: {resp3.get_content()} (Status: {resp3.get_status_code()})")
    
    # Test 4: Missing name parameter
    params4 = {}
    req4 = Request(params4)
    env4 = Environment(req4, "Hello, {{ name }}!")
    resp4 = home(env4)
    print(f"Test 4: {resp4.get_content()} (Status: {resp4.get_status_code()})")
    
    # Test 5: None environment
    resp5 = home(None)
    print(f"Test 5: {resp5.get_content()} (Status: {resp5.get_status_code()})")
