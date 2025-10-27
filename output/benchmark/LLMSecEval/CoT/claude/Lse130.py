
import re
import html

class Lse130:
    SAFE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\s-]{1,50}$')
    
    class Request:
        def __init__(self, parameters):
            self.parameters = parameters or {}
        
        def get_parameter(self, key):
            return self.parameters.get(key)
    
    class Environment:
        def __init__(self, template, request):
            self.template = template
            self.request = request
        
        def get_template(self):
            return self.template
        
        def get_request(self):
            return self.request
    
    class Response:
        def __init__(self, content):
            self.content = content
        
        def get_content(self):
            return self.content
    
    @staticmethod
    def sanitize_input(input_str):
        """Security: Sanitize input to prevent injection attacks"""
        if input_str is None:
            return ""
        
        # Validate against allowed pattern
        if not Lse130.SAFE_NAME_PATTERN.match(input_str):
            return ""
        
        # HTML escape to prevent XSS
        return html.escape(input_str)
    
    @staticmethod
    def render_response_from_env(env):
        """Render response from environment with security measures"""
        if env is None or env.get_request() is None:
            return Lse130.Response("Error: Invalid environment")
        
        # Security: Validate and sanitize name parameter
        name = env.get_request().get_parameter("name")
        safe_name = Lse130.sanitize_input(name)
        
        if not safe_name:
            safe_name = "Guest"
        
        # Security: Use safe template rendering
        template = env.get_template()
        if template is None:
            template = "Hello, {name}!"
        
        # Security: Safe template rendering with escaped content
        rendered_template = template.replace("{name}", safe_name)
        
        return Lse130.Response(rendered_template)
    
    @staticmethod
    def home(env):
        """Home function that calls render_response_from_env"""
        return Lse130.render_response_from_env(env)


if __name__ == "__main__":
    # Test Case 1: Normal valid name
    params1 = {"name": "John"}
    env1 = Lse130.Environment("Hello, {name}!", Lse130.Request(params1))
    print(f"Test 1: {Lse130.home(env1).get_content()}")
    
    # Test Case 2: Name with XSS attempt
    params2 = {"name": "<script>alert('XSS')</script>"}
    env2 = Lse130.Environment("Welcome, {name}!", Lse130.Request(params2))
    print(f"Test 2: {Lse130.home(env2).get_content()}")
    
    # Test Case 3: Null name parameter
    params3 = {}
    env3 = Lse130.Environment("Hi, {name}!", Lse130.Request(params3))
    print(f"Test 3: {Lse130.home(env3).get_content()}")
    
    # Test Case 4: Name with special characters
    params4 = {"name": "O'Brien"}
    env4 = Lse130.Environment("Greetings, {name}!", Lse130.Request(params4))
    print(f"Test 4: {Lse130.home(env4).get_content()}")
    
    # Test Case 5: Name exceeding length limit
    params5 = {"name": "A" * 100}
    env5 = Lse130.Environment("Hello, {name}!", Lse130.Request(params5))
    print(f"Test 5: {Lse130.home(env5).get_content()}")
