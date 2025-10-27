
import html
from typing import Dict, Optional

class Lse131:
    class Environment:
        """Mock Environment class to simulate template environment"""
        def __init__(self):
            self.templates = {
                "home.html": "Hello, {{name}}! Welcome to our secure application."
            }
        
        def get_template(self, template_name: str) -> str:
            return self.templates.get(template_name, "Template not found")
    
    class Request:
        """Mock Request class"""
        def __init__(self, name: str):
            self.parameters = {"name": name}
        
        def get_parameter(self, key: str) -> Optional[str]:
            return self.parameters.get(key)
    
    class Response:
        """Mock Response class"""
        def __init__(self, content: str):
            self.content = content
        
        def get_content(self) -> str:
            return self.content
        
        def __str__(self) -> str:
            return self.content
    
    @staticmethod
    def render_template(template: str, params: Dict[str, str]) -> str:
        """Render template with secure parameter substitution"""
        result = template
        for key, value in params.items():
            placeholder = "{{" + key + "}}"
            # HTML encode to prevent XSS
            safe_value = html.escape(value)
            result = result.replace(placeholder, safe_value)
        return result
    
    @staticmethod
    def render_response_from_env(env, request):
        """Render response from environment with secure handling"""
        # Get name parameter from request with validation
        name = request.get_parameter("name")
        
        # Input validation - prevent null and empty values
        if name is None or name.strip() == "":
            name = "Guest"
        
        # Length validation to prevent DoS
        if len(name) > 100:
            name = name[:100]
        
        # Get template from environment
        template = env.get_template("home.html")
        
        # Prepare parameters for rendering
        params = {"name": name}
        
        # Render template with secure parameter substitution
        rendered_content = Lse131.render_template(template, params)
        
        # Return response with rendered template
        return Lse131.Response(rendered_content)
    
    @staticmethod
    def home(env, request):
        """Home function that calls render_response_from_env"""
        return Lse131.render_response_from_env(env, request)


if __name__ == "__main__":
    env = Lse131.Environment()
    
    # Test case 1: Normal input
    req1 = Lse131.Request("Alice")
    resp1 = Lse131.home(env, req1)
    print(f"Test 1: {resp1}")
    
    # Test case 2: Input with special characters (XSS attempt)
    req2 = Lse131.Request("<script>alert('XSS')</script>")
    resp2 = Lse131.home(env, req2)
    print(f"Test 2: {resp2}")
    
    # Test case 3: Empty input
    req3 = Lse131.Request("")
    resp3 = Lse131.home(env, req3)
    print(f"Test 3: {resp3}")
    
    # Test case 4: Input with HTML tags
    req4 = Lse131.Request("<b>Bob</b>")
    resp4 = Lse131.home(env, req4)
    print(f"Test 4: {resp4}")
    
    # Test case 5: Input with quotes
    req5 = Lse131.Request("O'Reilly & Sons")
    resp5 = Lse131.home(env, req5)
    print(f"Test 5: {resp5}")
