import subprocess
import platform
import re

def ping_url(url: str) -> str:
    """
    Executes the ping command for a given URL in a secure way.

    Args:
        url: The URL or IP address to ping.

    Returns:
        The output of the ping command, or an error message if the input is invalid.
    """
    # Security: Validate input to allow only characters valid for a hostname.
    # This is a defense-in-depth measure against command injection.
    if not re.match(r'^[a-zA-Z0-9.-]+$', url):
        return "Error: Invalid characters in URL. Possible command injection attempt blocked."

    # Determine the correct ping command based on the operating system
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # Construct the command as a list of arguments.
    # This is the secure way to call subprocesses, as it avoids shell interpretation.
    command = ['ping', param, '4', url]
    
    try:
        # Execute the command
        # `capture_output=True` captures stdout and stderr.
        # `text=True` decodes them as text.
        # `check=False` prevents an exception on a non-zero exit code (e.g., host not found).
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        
        # Combine stdout and stderr for a complete log
        output = f"--- STDOUT ---\n{result.stdout}\n"
        if result.stderr:
            output += f"--- STDERR ---\n{result.stderr}\n"
        output += f"Process finished with exit code: {result.returncode}"
        return output
    except FileNotFoundError:
        return "Error: 'ping' command not found. Is it in your system's PATH?"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    test_urls = [
        "google.com",                  # Valid domain
        "8.8.8.8",                     # Valid IP address
        "nonexistent.domain.xyz",      # Should fail to resolve
        "127.0.0.1",                   # Localhost
        "google.com; ls"               # Command injection attempt
    ]

    for url in test_urls:
        print(f"--- Pinging: {url} ---")
        result = ping_url(url)
        print(result)
        print("----------------------------------\n")

if __name__ == "__main__":
    main()