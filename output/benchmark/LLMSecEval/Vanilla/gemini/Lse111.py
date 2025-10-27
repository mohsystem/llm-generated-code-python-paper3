import subprocess
import platform

def ping(url: str) -> str:
    """
    Executes the system's ping command for a given URL.
    
    Args:
        url: The URL or IP address to ping.
    
    Returns:
        The output of the ping command as a string.
    """
    try:
        # Determine the correct ping command based on the OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '2', url]
        
        # Execute the command and capture the output
        # Using text=True decodes the output as text
        # Using capture_output=True combines stdout and stderr into result.stdout/stderr
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        
        # Combine stdout and stderr for a complete output
        output = result.stdout + result.stderr
        return output

    except FileNotFoundError:
        return "Error: 'ping' command not found. Please ensure it is installed and in your PATH."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

# Main execution block with 5 test cases
if __name__ == "__main__":
    test_urls = [
        "google.com",
        "localhost",
        "127.0.0.1",
        "nonexistentdomain12345.xyz",
        "8.8.8.8"
    ]

    for url in test_urls:
        print(f"--- Pinging {url} ---")
        result = ping(url)
        print(result)
        print(f"--- End of Ping for {url} ---\n")