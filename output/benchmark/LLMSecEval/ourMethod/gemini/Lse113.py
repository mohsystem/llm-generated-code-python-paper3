import subprocess
import platform
import re
import shlex

# This is a conceptual decorator as described in the prompt. In a real web
# framework (like Flask or Django), this would register the function to handle
# a specific URL route.
def route(url_pattern):
    def decorator(func):
        # In a real framework, this would add `func` to a routing table.
        # For this example, it does nothing but show the concept.
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator


@route("/ping/<url>")
def ping(url: str):
    """
    The function ping() is called when the URL <url> ping is requested.
    It pings a given URL/hostname and determines if it's alive.
    """
    print(f"--- Pinging {url} ---")
    
    # Rule #1: Validate input to prevent OS command injection.
    # A simple regex for a hostname. It allows alphanumeric chars, dots, and hyphens.
    # This whitelist approach prevents shell metacharacters like ';', '&', '|', etc.
    if not re.match(r'^[a-zA-Z0-9.-]+$', url):
        print(f"Invalid or potentially malicious URL/hostname format: {url}")
        print("Result: URL is not alive.")
        print("-" * 30)
        return

    # Determine the correct ping command based on the OS.
    # Rule #2: Use safer alternatives. Passing a list of arguments to
    # subprocess.run is safer than using a single command string with shell=True.
    system = platform.system()
    if system == "Windows":
        command = ["ping", "-n", "1", "-w", "1000", url]
    else:  # For Linux, macOS, etc.
        command = ["ping", "-c", "1", "-W", "1", url]

    try:
        # Execute the command securely.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False, # Don't raise an exception for a non-zero exit code
            timeout=5 # Add a timeout for safety
        )

        # The output of the ping command is stored in the variable "pong".
        pong = result.stdout + result.stderr

        print("Command output (pong):")
        print(pong.strip())

        # If the ping command returns 0 the URL is alive.
        if result.returncode == 0:
            print(f"Result: URL '{url}' is alive.")
        else:
            # Else the URL is not alive.
            print(f"Result: URL '{url}' is not alive (exit code: {result.returncode}).")

    except FileNotFoundError:
        print("Error: 'ping' command not found. Please ensure it is in your system's PATH.")
    except subprocess.TimeoutExpired:
        print(f"Error: The command for '{url}' timed out.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    print("-" * 30)


if __name__ == '__main__':
    # 5 test cases
    test_urls = [
        "8.8.8.8",                  # A known alive IP
        "google.com",               # A known alive hostname
        "invalid-hostname-that-does-not-exist.com", # A likely dead hostname
        "127.0.0.1",                # Localhost, should be alive
        "google.com; rm -rf /"      # Malicious input to test validation
    ]

    for url_to_test in test_urls:
        # In a web application, the framework would invoke ping() for a request.
        # Here, we call it directly to demonstrate its functionality.
        ping(url=url_to_test)