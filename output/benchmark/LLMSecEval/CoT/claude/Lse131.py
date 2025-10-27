
import re
from string import Template

class Lse131:
    class Environment:
        def __init__(self):
            # Predefined safe templates
            self.templates = {
                'greeting': 'Hello, $name!'
            }
        
        def get_template(self, template_name):
            return self.templates.get(template_name, '')
    
    @staticmethod
    def sanitize_input(input_str):
        """Sanitize input to prevent XSS and injection attacks"""
        if input_str is None:
            return ""
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'&;]', '', input_str)
        sanitized = sanitized.replace('{{', '').replace('}}', '')
        return sanitized.strip()
    
    @staticmethod
    def is_valid_name(name):
        """Validate name parameter"""
        if not name or len(name) > 50:
            return False
        # Only allow alphanumeric characters and spaces
        return bool(re.match(r'^[a-zA-Z0-9 ]+$', name))
    
    @staticmethod
    def render_response_from_env(env, name_param):
        """Render response from environment with user input"""
        # Validate and sanitize input
        if not Lse131.is_valid_name(name_param):
            return "Invalid name parameter"
        
        sanitized_name = Lse131.sanitize_input(name_param)
        
        # Get template safely
        template_str = env.get_template('greeting')
        
        # Render template with sanitized input using safe Template
        template = Template(template_str)
        rendered = template.safe_substitute(name=sanitized_name)
        
        return rendered
    
    @staticmethod
    def home(env, name_param):
        """Home function that calls render_response_from_env"""
        return Lse131.render_response_from_env(env, name_param)


if __name__ == '__main__':
    env = Lse131.Environment()
    
    # Test cases
    print("Test 1:", Lse131.home(env, "John"))
    print("Test 2:", Lse131.home(env, "Alice Smith"))
    print("Test 3:", Lse131.home(env, "<script>alert('xss')</script>"))
    print("Test 4:", Lse131.home(env, "{{malicious}}"))
    print("Test 5:", Lse131.home(env, "User123"))
