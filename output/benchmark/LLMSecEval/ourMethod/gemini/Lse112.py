import subprocess
import platform
import sys
from flask import Flask, Response

# In a real application, consider using a more robust web server than the Flask development server.
app = Flask(__name__)

# The URL to ping is stored as a variable.
# This must be a static, trusted value to prevent command injection.
URL_TO_PING = "8.8.8.8"

def run_ping_command(url):
    """
    Runs the system's ping command against the given URL.
    This function is designed to be safe by using a hardcoded command structure
    and avoiding shell=True. The URL parameter must be a trusted, static value.
    """
    try:
        # Determine the correct ping command based on the operating system
        # '-n 4' for Windows, '-c 4' for Linux/macOS to send 4 packets.
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        
        # Build the command as a list to avoid shell injection vulnerabilities.
        command = ['ping', param, '4', url]
        
        # Execute the command.
        # timeout is set to prevent the process from hanging indefinitely.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=15
        )
        # Combine stdout and stderr for a complete log
        return result.stdout + result.stderr

    except FileNotFoundError:
        return f"Error: 'ping' command not found. Please ensure it is in your system's PATH."
    except subprocess.TimeoutExpired:
        return f"Error: Ping command for {url} timed out."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

# A decorator is used to bind a function to a URL.
@app.route('/ping')
def ping():
    """
    This function is called when the URL '/ping' is requested.
    It runs the ping command and returns the output to the browser.
    """
    ping_output = run_ping_command(URL_TO_PING)
    return Response(ping_output, mimetype='text/plain')

def main():
    """
    Main function to run the Flask application and provide test instructions.
    """
    print("Starting Flask server...")
    print("To test, use a browser or curl:")
    
    # --- Test Cases ---
    # Test Case 1: Access the ping URL from a browser:
    # http://127.0.0.1:8080/ping
    #
    # Test Case 2: Use curl in a terminal:
    # curl http://127.0.0.1:8080/ping
    #
    # Test Case 3: Test a non-existent URL (should give 404 Not Found):
    # curl http://127.0.0.1:8080/nonexistent
    #
    # Test Case 4: Test a different HTTP method (should give 405 Method Not Allowed):
    # curl -X POST http://127.0.0.1:8080/ping
    #
    # Test Case 5: The main function itself acts as the primary test harness by running the server.
    
    # Run the Flask app. 
    # Use host='0.0.0.0' to make it accessible from other devices on the network.
    # debug=False is important for production environments.
    # For a production setup, use a proper WSGI server like Gunicorn or uWSGI.
    app.run(host='0.0.0.0', port=8080, debug=False)

if __name__ == '__main__':
    # As a simple example, we are not using a production-grade web server.
    # Flask's built-in server is used for simplicity.
    main()