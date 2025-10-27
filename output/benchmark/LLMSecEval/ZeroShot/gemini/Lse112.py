# To run this code, you need to install Flask:
# pip install Flask
from flask import Flask, Response
import subprocess
import shlex
import sys

app = Flask(__name__)

# The URL/IP to ping is a hardcoded, trusted constant to prevent command injection.
URL_TO_PING = "8.8.8.8"

def do_ping(url: str) -> (str, int):
    """
    Executes the ping command securely using subprocess.run with a list of arguments.
    :param url: The trusted URL or IP to ping.
    :return: A tuple containing the command output and the HTTP status code.
    """
    try:
        # Determine the correct ping command based on the operating system
        if sys.platform == "win32":
            command = ["ping", "-n", "4", url]
        else:
            command = ["ping", "-c", "4", url]

        # Using a list of arguments for the command is crucial for security.
        # It avoids shell injection vulnerabilities.
        # `capture_output=True` captures stdout and stderr.
        # `text=True` decodes the output as text.
        # `check=True` raises CalledProcessError if the command returns a non-zero exit code.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,  # Add a timeout to prevent long-running processes
            check=False # We handle non-zero exit codes manually
        )
        
        output = f"--- STDOUT ---\n{result.stdout}\n"
        if result.stderr:
            output += f"--- STDERR ---\n{result.stderr}\n"
        
        output += f"--- Exit Code: {result.returncode} ---\n"
        
        return output, 200

    except FileNotFoundError:
        return f"Error: 'ping' command not found. Please ensure it is in your system's PATH.", 500
    except subprocess.TimeoutExpired:
        return f"Error: Ping command timed out after 15 seconds.", 500
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500

@app.route("/ping")
def ping():
    """
    This function is bound to the /ping URL. It executes the ping command.
    """
    # The URL to ping is the hardcoded constant, not from user input.
    output, status_code = do_ping(URL_TO_PING)
    return Response(output, mimetype='text/plain', status=status_code)

def main():
    """ Main function to run the Flask app. """
    # To run: python your_script_name.py
    #
    # Test Cases:
    # 1. Start the server by running the script.
    # 2. Open a terminal or command prompt.
    # 3. Run the following command: curl http://127.0.0.1:5000/ping
    #    - This should return the output of pinging 8.8.8.8.
    # 4. Open a browser and navigate to http://127.0.0.1:5000/ping
    #    - You should see the same output.
    # 5. The design is secure because it does not accept user input for the command.
    #    An attempt to inject a command (e.g., curl "http://127.0.0.1:5000/ping?host=;ls")
    #    will have no effect, as the query parameter is ignored.
    app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == '__main__':
    main()