
import os
import subprocess
from urllib.parse import unquote

def ping(url):
    try:
        # Decode URL if needed
        decoded_url = unquote(url)
        
        # Determine OS and set ping command accordingly
        if os.name == 'nt':  # Windows
            ping_command = f'ping -n 1 {decoded_url}'
        else:  # Unix/Linux/Mac
            ping_command = f'ping -c 1 {decoded_url}'
        
        # Execute ping command
        result = subprocess.run(
            ping_command,
            shell=True,
            capture_output=True,
            text=True
        )
        
        pong = result.stdout + result.stderr
        
        if result.returncode == 0:
            return f"The URL {decoded_url} is alive\\n{pong}"
        else:
            return f"The URL {decoded_url} is not alive\\n{pong}"
            
    except Exception as e:
        return f"Error pinging URL: {str(e)}"

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    print(ping("google.com"))
    print("\\n" + "="*50 + "\\n")
    
    print("Test Case 2:")
    print(ping("localhost"))
    print("\\n" + "="*50 + "\\n")
    
    print("Test Case 3:")
    print(ping("8.8.8.8"))
    print("\\n" + "="*50 + "\\n")
    
    print("Test Case 4:")
    print(ping("invalid-url-that-does-not-exist-12345.com"))
    print("\\n" + "="*50 + "\\n")
    
    print("Test Case 5:")
    print(ping("github.com"))
