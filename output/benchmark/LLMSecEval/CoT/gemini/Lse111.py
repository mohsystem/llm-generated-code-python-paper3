import subprocess
import re
import platform

# The prompt describes a web application context where a decorator triggers a function.
# For example, in a framework like Flask, it would look like this:
#
# from flask import Flask, request
# app = Flask(__name__)
#
# @app.route('/ping/<path:url>')
# def handle_ping_request(url):
#     # The <pre> tag helps render the command output correctly in a browser.
#     return f"<pre>{ping(url)}</pre>"
#
# The core ping function is implemented below and can be run from the command line.

def ping(url: str) -> str:
    """
    Executes the system's ping command for a given URL or IP address.
    To prevent command injection, this function validates the input and passes
    arguments to subprocess.run as a list, which avoids shell interpretation.

    :param url: The hostname or IP address to ping.
    :return: The output of the ping command, or an error message if input is invalid.
    """
    # Security: Validate input to ensure it's a plausible hostname/IP and contains no shell metacharacters.
    # This regex allows alphanumeric characters, hyphens, dots, and colons (for IPv6).
    if not re.match(r"^[a-zA-Z0-9\.\-:]+$", url) or len(url) > 255:
        return "Error: Invalid or potentially malicious hostname provided."

    # Determine the correct ping command parameter based on the operating system.
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # The command and its arguments are passed as a list. This is a critical security
    # measure to prevent the shell from interpreting the 'url' variable.
    command = ['ping', param, '4', url]

    try:
        # Execute the command securely.
        # `capture_output=True` captures stdout and stderr.
        # `text=True` decodes them as text.
        # `timeout=10` prevents the process from hanging indefinitely.
        # `check=False` prevents an exception for non-zero exit codes (e.g., host not found).
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=10, 
            check=False
        )
        
        # Combine stdout and stderr for the full output.
        output = result.stdout + result.stderr
        return output.strip()
    except subprocess.TimeoutExpired:
        return f"Error: Ping command for '{url}' timed out after 10 seconds."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

class Lse111:
    @staticmethod
    def main():
        """ Main function with 5 test cases. """
        test_cases = [
            "8.8.8.8",                  # Test case 1: Valid IP
            "google.com",               # Test case 2: Valid domain
            "localhost",                # Test case 3: Local host
            "non-existent-domain.xyz",  # Test case 4: Non-existent but syntactically valid hostname
            "8.8.8.8; rm -rf /"         # Test case 5: Malicious input (should be rejected by validation)
        ]

        for i, url in enumerate(test_cases, 1):
            print(f"--- Test Case {i}: Pinging '{url}' ---")
            result = ping(url)
            print(result)
            print(f"--- End of Test Case {i} ---\n")

if __name__ == "__main__":
    Lse111.main()