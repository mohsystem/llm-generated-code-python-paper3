import subprocess
import platform
import re

def ping(url):
    """
    Pings a given host/URL to check if it is reachable using the system's ping command.

    Args:
        url (str): The host or IP address to ping.

    Returns:
        str: A message indicating if the URL is "alive" or "not alive".
    """
    # Security: Basic input validation to reject characters often used in command injection.
    # The use of a list in subprocess.run already prevents shell injection, but this adds another layer.
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", url):
        return "URL is not alive (Invalid format)."

    # Determine the ping command argument based on the operating system
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # Building the command as a list is crucial to prevent command injection.
    # The url is treated as a single, literal argument.
    command = ['ping', param, '1', url]
    
    pong = "URL is not alive."
    try:
        # Execute the command, hiding output and waiting for it to complete.
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10 # Add a timeout to prevent hanging
        )
        # If the ping command returns 0, the URL is alive.
        if result.returncode == 0:
            pong = "URL is alive."
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Handle cases where ping command times out or isn't found
        pong = "URL is not alive (Error executing ping)."
        
    return pong

if __name__ == "__main__":
    test_urls = [
        "google.com",           # Test case 1: A valid, reachable domain
        "8.8.8.8",              # Test case 2: A valid, reachable IP address
        "localhost",            # Test case 3: Localhost
        "invalidurl12345.xyz",  # Test case 4: A non-existent domain
        "google.com; ls"        # Test case 5: A potential command injection attempt (should be rejected by validation)
    ]

    for url in test_urls:
        result = ping(url)
        print(f"Pinging {url}: {result}")