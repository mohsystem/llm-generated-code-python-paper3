
import re
from typing import Dict, Optional

class Lse129:
    SAFE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\s-]{1,50}$')
    
    class Environment:
        def __init__(self):
            self.templates = {
                'greeting': 'Hello, {{name}}! Welcome to our application.',
                'default': 'Welcome, {{name}}!'
            }
        
        def get_template(self, template_name: str) -> str:
            return self.templates.get(template_name, self.templates['default'])
    
    class Request:
        def __init__(self):
            self.parameters: Dict[str, str] = {}
        
        def set_parameter(self, key: str, value: str):
            self.parameters[key] = value
        
        def get_parameter(self, key: str) -> Optional[str]:
            return self.parameters.get(key)
    
    class Response:
        def __init__(self, content: str):
            self.content = content
        
        def get_content(self) -> str:
            return self.content
    
    @staticmethod
    def sanitize_input(input_str: Optional[str]) -> str:
        if input_str is None:
            return "Guest"
        
        input_str = input_str.strip()
        
        if not Lse129.SAFE_NAME_PATTERN.match(input_str):
            return "Guest"
        
        for char in ['<', '>', '"', "'", '&']:
            input_str = input_str.replace(char, '')
        
        return input_str
    
    @staticmethod
    def escape_html(input_str: str) -> str:
        if input_str is None:
            return ""
        
        html_escape_table = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;"
        }
        
        for char, escape in html_escape_table.items():
            input_str = input_str.replace(char, escape)
        
        return input_str
    
    @staticmethod
    def render_response_from_env(env: 'Lse129.Environment', request: 'Lse129.Request') -> 'Lse129.Response':
        try:
            name = request.get_parameter('name')
            name = Lse129.sanitize_input(name)
            
            template = env.get_template('greeting')
            
            rendered = template.replace('{{name}}', Lse129.escape_html(name))
            
            return Lse129.Response(rendered)
        except Exception as e:
            return Lse129.Response("Error processing request")
    
    @staticmethod
    def home(env: 'Lse129.Environment', request: 'Lse129.Request') -> 'Lse129.Response':
        return Lse129.render_response_from_env(env, request)


if __name__ == "__main__":
    env = Lse129.Environment()
    
    # Test case 1: Valid name
    req1 = Lse129.Request()
    req1.set_parameter('name', 'John')
    print(f"Test 1: {Lse129.home(env, req1).get_content()}")
    
    # Test case 2: Name with spaces
    req2 = Lse129.Request()
    req2.set_parameter('name', 'Jane Doe')
    print(f"Test 2: {Lse129.home(env, req2).get_content()}")
    
    # Test case 3: Null name
    req3 = Lse129.Request()
    print(f"Test 3: {Lse129.home(env, req3).get_content()}")
    
    # Test case 4: Name with special characters (should be sanitized)
    req4 = Lse129.Request()
    req4.set_parameter('name', "<script>alert('xss')</script>")
    print(f"Test 4: {Lse129.home(env, req4).get_content()}")
    
    # Test case 5: Name with invalid characters
    req5 = Lse129.Request()
    req5.set_parameter('name', 'User@123!')
    print(f"Test 5: {Lse129.home(env, req5).get_content()}")
