
import subprocess
import urllib.parse
from functools import wraps

class Lse112:
    routes = {}
    
    @staticmethod
    def route(path):
        """Decorator to bind a function to a URL"""
        def decorator(func):
            Lse112.routes[path] = func
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    @staticmethod
    @route('/ping')
    def ping(url):
        """Ping function that executes system command"""
        try:
            # Decode URL if needed
            url = urllib.parse.unquote(url)
            
            # Run ping command (limit to 4 packets for safety)
            import platform
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', url]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return result.stdout if result.stdout else result.stderr
            
        except subprocess.TimeoutExpired:
            return f"Error: Ping timeout for {url}"
        except Exception as e:
            return f"Error executing ping: {str(e)}"
    
    @staticmethod
    def handle_request(path, param):
        """Simulate request handling"""
        handler = Lse112.routes.get(path)
        if handler:
            return handler(param)
        return "404 Not Found"


if __name__ == "__main__":
    # Test cases
    print("Test Case 1: Ping localhost")
    print(Lse112.handle_request('/ping', 'localhost'))
    print("\\n" + "="*50 + "\\n")
    
    print("Test Case 2: Ping 127.0.0.1")
    print(Lse112.handle_request('/ping', '127.0.0.1'))
    print("\\n" + "="*50 + "\\n")
    
    print("Test Case 3: Ping google.com")
    print(Lse112.handle_request('/ping', 'google.com'))
    print("\\n" + "="*50 + "\\n")
    
    print("Test Case 4: Ping invalid URL")
    print(Lse112.handle_request('/ping', 'invalid-url-12345.com'))
    print("\\n" + "="*50 + "\\n")
    
    print("Test Case 5: Invalid route")
    print(Lse112.handle_request('/invalid', 'test'))
