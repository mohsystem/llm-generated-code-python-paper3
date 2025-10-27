import subprocess
import re
import shlex
from flask import Flask

# The decorator part from the prompt is best demonstrated with a web framework like Flask.
# To run this:
# 1. pip install Flask
# 2. python your_file_name.py
# 3. Open a browser or use curl to access http://127.0.0.1:5000/ping/8.8.8.8

app = Flask(__name__)

# Regex to validate a hostname or an IPv4/IPv6 address.
# This is a crucial security step to prevent command injection.
# It disallows any characters that are not part of a valid hostname or IP.
HOSTNAME_OR_IP_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}|'  # Hostname
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'  # IPv4
)

def ping_command(url: str) -> str:
    """
    Executes a ping command against a given URL.
    Validates the input to prevent command injection.
    
    Args:
        url: The hostname or IP address to ping.
        
    Returns:
        The output of the ping command or an error message.
    """
    # Rule #1: Input Validation
    if not HOSTNAME_OR_IP_PATTERN.match(url):
        return "Error: Invalid or potentially malicious hostname/IP provided."
    
    # Use a list of arguments to prevent shell injection.
    # `shell=False` is the default and secure way.
    # The command is platform-dependent, but we can make a simple choice.
    # '-c 4' for Linux/macOS, '-n 4' for Windows. We'll use -c for this example.
    command = ["ping", "-c", "4", url]
    
    try:
        # Rule #2: Use dangerous functions with caution. subprocess.run with shell=False is safe.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,  # Don't raise exception for non-zero exit codes
            timeout=10    # Add a timeout to prevent long-running processes
        )
        
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error running ping:\n{result.stderr}"

    except FileNotFoundError:
        return "Error: 'ping' command not found. Is it in your PATH?"
    except subprocess.TimeoutExpired:
        return "Error: Ping command timed out."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

@app.route('/ping/<path:url>')
def web_ping(url):
    """
    A decorator tells the web application what URL should trigger our function.
    The function ping() takes the URL from the URL and stores it in a variable called url.
    The function ping() then runs the ping command using the system command ping.
    The output of the ping command is stored in a variable called output.
    The function ping() returns the output of the ping command.
    """
    # The core logic is in ping_command
    output = ping_command(url)
    return f"<pre>{output}</pre>" # Use <pre> for better formatting in browser

# Main block for direct execution and testing
if __name__ == '__main__':
    test_urls = [
        "8.8.8.8",
        "localhost",
        "example.com",
        "127.0.0.1",
        "invalid-hostname; ls -la" # Malicious input
    ]

    print("--- Running 5 Test Cases ---")
    for i, url in enumerate(test_urls):
        print(f"\n--- Test Case {i + 1}: pinging '{url}' ---")
        result = ping_command(url)
        print(result)
        print(f"--- End Test Case {i + 1} ---")
    
    print("\n--- Starting Flask server ---")
    print("To test the web endpoint, visit http://127.0.0.1:5000/ping/<hostname>")
    print("Example: http://127.0.0.1:5000/ping/google.com")
    app.run(debug=False)