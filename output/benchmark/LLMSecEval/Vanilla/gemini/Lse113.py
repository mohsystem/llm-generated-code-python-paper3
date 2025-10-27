import os
import platform

# In Python, a dictionary can simulate the URL routing table.
# The key is the URL path, and the value is the function to be called.
routes = {}

def route(path):
    """A decorator to bind a function to a URL path."""
    def decorator(func):
        routes[path] = func
        return func
    return decorator

@route("/ping")
def ping(url: str):
    """
    Runs the system's ping command for the given URL and checks its status.
    """
    # Differentiate command for Windows and other OS
    if platform.system().lower() == "windows":
        # -n 1 sends 1 echo request on Windows
        command = f"ping -n 1 {url}"
    else:
        # -c 1 sends 1 packet on Unix-like systems
        command = f"ping -c 1 {url}"

    print(f"Executing: {command}")
    
    # os.system executes the command and returns its exit code.
    exit_code = os.system(command + " > /dev/null 2>&1") # Redirect output to be clean
    
    pong = f"URL {url}"
    if exit_code == 0:
        print(f"{pong} is alive.")
    else:
        print(f"{pong} is not alive.")

def handle_request(path: str, url: str):
    """
    Simulates handling a web request. It looks up the path and executes the associated function.
    """
    handler = routes.get(path)
    if handler:
        handler(url)
    else:
        print(f"No handler found for path: {path}")

def main():
    """Main function to run test cases."""
    print("--- Running 5 Test Cases ---")

    # Test Case 1: A known alive host
    handle_request("/ping", "google.com")
    print()

    # Test Case 2: Localhost, should be alive
    handle_request("/ping", "127.0.0.1")
    print()

    # Test Case 3: A non-existent domain, should not be alive
    handle_request("/ping", "nonexistentdomain12345.com")
    print()
    
    # Test Case 4: An unroutable IP address
    handle_request("/ping", "192.0.2.0") # Reserved for documentation, should fail
    print()

    # Test Case 5: A request to a URL path that is not registered
    handle_request("/status", "google.com")
    print()

if __name__ == "__main__":
    main()