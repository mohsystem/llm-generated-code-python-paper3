import html

# In Python, a decorator can create this mapping directly.
# However, to keep the structure similar to other languages,
# we will use a dictionary to simulate the routing table.
ROUTES = {}

def route(path_prefix):
    """A decorator that maps a URL prefix to a function."""
    def decorator(func):
        ROUTES[path_prefix] = func
        return func
    return decorator

def escape(s):
    """Wrapper for html.escape to match the problem description."""
    return html.escape(s)

@route("/hello/")
def hello(username):
    """
    Returns a string with the text Hello followed by the escaped username.
    """
    return f"Hello, {escape(username)}!"

def handle_request(url):
    """
    Finds the correct function for the URL and calls it with the parameter.
    """
    for prefix, handler_func in ROUTES.items():
        if url.startswith(prefix):
            # Extract parameter from the URL
            param = url[len(prefix):]
            return handler_func(param)
    return "404 Not Found"

def main():
    """Main function with 5 test cases."""
    print("Test Case 1: Simple username")
    print(f"Input: /hello/Alice")
    print(f"Output: {handle_request('/hello/Alice')}\n")
    
    print("Test Case 2: Username with HTML characters")
    print(f"Input: /hello/<script>alert('XSS')</script>")
    print(f"Output: {handle_request('/hello/<script>alert(\'XSS\')</script>')}\n")
    
    print("Test Case 3: Empty username")
    print(f"Input: /hello/")
    print(f"Output: {handle_request('/hello/')}\n")
    
    print("Test Case 4: Mismatched URL")
    print(f"Input: /goodbye/Bob")
    print(f"Output: {handle_request('/goodbye/Bob')}\n")

    print("Test Case 5: Username with various special characters")
    print(f"Input: /hello/Tom & Jerry > \"The Movie\"")
    print(f"Output: {handle_request('/hello/Tom & Jerry > \"The Movie\"')}\n")

if __name__ == "__main__":
    main()