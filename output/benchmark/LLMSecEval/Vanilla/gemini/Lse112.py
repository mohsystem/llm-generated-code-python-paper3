# Before running, you must install Flask:
# pip install Flask

import subprocess
import re
import platform
from flask import Flask, request

# The decorator is used to bind this function to the /ping URL.
app = Flask(__name__)

def execute_ping(url):
    """
    Executes the system's ping command for a given URL.
    :param url: The URL or IP address to ping.
    :return: The output of the ping command as a string.
    """
    # Basic validation to prevent command injection.
    if not url or not re.match(r'^[a-zA-Z0-9.\-]+$', url):
        return "Error: Invalid or potentially malicious URL format provided."

    # Determine the correct ping command based on the OS
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', url]

    try:
        # Execute the command, capture output, and set a timeout.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        # Return stdout if successful, otherwise return stderr.
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error executing ping:\n{result.stderr}"
    except subprocess.TimeoutExpired:
        return "Ping command timed out after 10 seconds."
    except FileNotFoundError:
        return "Error: 'ping' command not found. Is it in your system's PATH?"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"

@app.route('/ping')
def ping_from_request():
    """
    This function is called when the '/ping' URL is requested.
    It gets the URL from the query parameters and returns the ping result.
    """
    url_to_ping = request.args.get('url')
    if not url_to_ping:
        return "Please provide a URL to ping. Example: /ping?url=google.com", 400
    
    ping_result = execute_ping(url_to_ping)
    # Return the result as plain text
    return ping_result, 200, {'Content-Type': 'text/plain; charset=utf-8'}


def run_test_cases():
    """Runs 5 test cases directly from the command line."""
    print("--- Running 5 Command-Line Test Cases ---")
    test_urls = [
        "google.com",               # Valid domain
        "127.0.0.1",                # Localhost IP
        "8.8.8.8",                  # Public IP
        "nonexistent-domain-1234.com", # Invalid domain
        "google.com; ls -la"        # Malicious input attempt
    ]

    for url in test_urls:
        print(f"\n--- Pinging: {url} ---")
        result = execute_ping(url)
        print(result)

if __name__ == '__main__':
    # 1. Run 5 test cases and print results to console
    run_test_cases()
    
    # 2. Start the web server
    port = 5000
    print(f"\n--- Starting Flask Web Server on port {port} ---")
    print("To test the server, open a browser or use curl with the following URLs:")
    print(f"  curl 'http://localhost:{port}/ping?url=google.com'")
    print(f"  curl 'http://localhost:{port}/ping?url=1.1.1.1'")
    print("Server started. Press Ctrl+C to stop.")
    # Use debug=False for production
    app.run(host='0.0.0.0', port=port, debug=False)