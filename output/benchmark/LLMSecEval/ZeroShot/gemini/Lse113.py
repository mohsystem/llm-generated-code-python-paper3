import subprocess
import platform
import re

def ping_url(url: str):
    """
    Pings a URL and checks if it's alive. The function is designed to be secure
    by validating the input and by not using a shell to execute the command.
    """
    # Security: Validate hostname format to allow only alphanumeric chars, dots, and hyphens.
    # This prevents command injection characters from being passed to the command list.
    if not isinstance(url, str) or not re.match(r"^[a-zA-Z0-9.-]+$", url):
        pong = "Error: Invalid characters in URL. Only alphanumerics, hyphens, and dots are allowed."
        return f"URL '{url}' is invalid.", pong

    # Determine the correct ping command parameters based on the OS
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # The command is a list of arguments to avoid shell interpretation (preventing injection)
    command = ['ping', param, '4', url]

    try:
        # Execute the command without a shell
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=10, 
            check=False
        )

        pong = result.stdout + result.stderr

        if result.returncode == 0:
            return f"The URL '{url}' is alive.", pong
        else:
            return f"The URL '{url}' is not alive.", pong

    except FileNotFoundError:
        pong = "Error: 'ping' command not found. Is it in your system's PATH?"
        return f"The URL '{url}' could not be checked.", pong
    except subprocess.TimeoutExpired:
        pong = f"Error: Ping command for '{url}' timed out after 10 seconds."
        return f"The URL '{url}' is not alive (timeout).", pong
    except Exception as e:
        pong = f"An unexpected error occurred: {e}"
        return f"The URL '{url}' could not be checked.", pong

def main():
    """ Main function with test cases """
    test_urls = [
        "8.8.8.8",
        "invalid-hostname-that-does-not-exist-12345.com",
        "127.0.0.1",
        "google.com",
        "google.com; ls -la" # Malicious input
    ]

    for url in test_urls:
        status, pong = ping_url(url)
        print(f"--- Testing URL: {url} ---")
        print(f"Status: {status}")
        print("Output (pong):")
        print(pong)
        print("-" * 25)

if __name__ == "__main__":
    main()