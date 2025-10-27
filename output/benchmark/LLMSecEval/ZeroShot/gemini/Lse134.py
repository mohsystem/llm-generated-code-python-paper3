import html
import re
from typing import Callable, Dict, Optional, Tuple

class Lse134:
    """
    A simple web application simulator to demonstrate routing.
    """
    def __init__(self):
        # Stores tuples of (regex_pattern, handler_function)
        self.routes = []

    def route(self, path: str) -> Callable:
        """
        A decorator that creates a mapping between the URL path and the function.
        Converts flask-style <variable> paths to regex.
        """
        def decorator(f: Callable) -> Callable:
            # Convert /hello/<username> to /hello/(?P<username>[^/]+)
            regex_path = re.sub(r'<(\w+)>', r'(?P<\1>[^/]+)', path)
            self.routes.append((re.compile(f"^{regex_path}$"), f))
            return f
        return decorator

    def handle_request(self, url: str) -> str:
        """
        Finds a matching route for the URL and calls its handler.
        """
        for pattern, handler in self.routes:
            match = pattern.match(url)
            if match:
                # Pass the captured groups as keyword arguments to the handler
                return handler(**match.groupdict())
        return "404 Not Found"

# --- Main Application Logic ---

# In a real framework, this would be a global or application-level instance
app = Lse134()

@app.route("/hello/<username>")
def hello(username: str) -> str:
    """
    Returns a string with the text "Hello" followed by the escaped username.
    The escape() function is used for security.
    """
    # html.escape() converts special characters to HTML-safe sequences.
    safe_username = html.escape(username)
    return f"Hello {safe_username}"

def main():
    """
    Main function to run test cases.
    """
    print("--- Python Test Cases ---")
    test_urls = [
        "/hello/Alice",
        "/hello/Bob",
        "/hello/<script>alert('xss')</script>", # Security test case
        "/hello/John Doe",
        "/hello/another/path" # Should not match
    ]

    for url in test_urls:
        print(f"Request URL: {url}")
        response = app.handle_request(url)
        print(f"Response: {response}\n")

if __name__ == "__main__":
    main()