import html
import re
from typing import Callable, Dict, Optional

# This dictionary simulates a web app's routing table.
# The keys are URL patterns (regex) and values are the handler functions.
ROUTES: Dict[str, Callable] = {}

def route(url_pattern: str) -> Callable:
    """
    A decorator that creates a mapping between the URL pattern and the function.
    It converts Flask-style <variable> syntax to a named regex group.
    """
    def decorator(func: Callable) -> Callable:
        # Convert /hello/<username> to ^/hello/(?P<username>[^/]+)$
        regex_pattern = re.sub(r'<([^>]+)>', r'(?P<\1>[^/]+)', url_pattern)
        regex_pattern = f"^{regex_pattern}$"
        ROUTES[regex_pattern] = func
        return func
    return decorator

def escape(s: str) -> str:
    """
    Converts special characters to HTML-safe sequences.
    This is a wrapper around html.escape for clarity.
    """
    return html.escape(s)

@route('/hello/<username>')
def hello(username: str) -> str:
    """
    Returns a safe HTML greeting for the given username.
    """
    return f"Hello {escape(username)}"

def handle_request(url: str) -> str:
    """
    Simulates a request dispatcher. It finds a matching route for the given
    URL and calls the associated handler function with the extracted arguments.
    """
    for pattern, handler in ROUTES.items():
        match = re.match(pattern, url)
        if match:
            # Pass the named groups from the regex as keyword arguments to the handler
            return handler(**match.groupdict())
    return "404 Not Found"

def main():
    """Main function with 5 test cases."""
    print("Python Test Cases:")
    test_urls = [
        "/hello/World",
        "/hello/Jane Doe",
        "/hello/<script>alert('XSS')</script>",
        "/hello/user&'\"<>",
        # The regex pattern [^/]+ requires at least one character.
        # To test an empty username, we would need a different route or pattern.
        # Let's add a route for it.
        "/hello/" 
    ]

    # Add a specific route for the empty case, as the main pattern requires a username.
    @route('/hello/')
    def hello_empty():
        return "Hello "
    
    for url in test_urls:
        print(f"Request: {url}")
        print(f"Response: {handle_request(url)}")
        print("---")


if __name__ == "__main__":
    main()