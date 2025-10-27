import subprocess
import re
import platform

def ping(url: str) -> str:
    """
    Executes the ping command for a given URL in a secure way.

    Args:
        url: The URL or IP address to ping.

    Returns:
        The output of the ping command, or an error message if the input is invalid or an error occurs.
    """
    if not isinstance(url, str) or not url.strip():
        return "Error: URL must be a non-empty string."

    # Security: Validate the input to ensure it is a valid hostname or IP address.
    # This regex is reasonably strict to prevent command injection.
    # It allows for hostnames (e.g., example.com) and IPv4 addresses.
    hostname_pattern = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"
        r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    )
    ipv4_pattern = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    if not hostname_pattern.match(url) and not ipv4_pattern.match(url):
        return "Error: Invalid hostname or IP address format."

    try:
        # Determine OS to use appropriate ping command arguments
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        
        # Security: Use a list of arguments for subprocess.run.
        # This prevents the shell from interpreting the 'url' variable,
        # which is the primary defense against command injection.
        command = ['ping', param, '4', url]
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False, # We will check the return code manually
            timeout=10   # Add a timeout to prevent indefinite hanging
        )
        
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += result.stderr
        
        if result.returncode != 0:
            output += f"\nPing command exited with error code: {result.returncode}"
            
        return output

    except FileNotFoundError:
        return "Error: 'ping' command not found. Please ensure it is in your system's PATH."
    except subprocess.TimeoutExpired:
        return f"Error: Timeout expired for pinging {url}."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

if __name__ == '__main__':
    test_urls = [
        "8.8.8.8",                  # Valid IP
        "google.com",               # Valid hostname
        "localhost",                # Valid hostname
        "invalid-hostname-",        # Invalid hostname
        "8.8.8.8; ls -la"           # Malicious command injection attempt
    ]

    for url in test_urls:
        print(f"--- Pinging: {url} ---")
        response = ping(url)
        print(response)
        print("----------------------------------\n")