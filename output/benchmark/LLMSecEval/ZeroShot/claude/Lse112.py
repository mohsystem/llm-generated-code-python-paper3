
import subprocess
import re
import urllib.parse

def is_valid_url(url):
    """Validates URL to prevent command injection"""
    if not url or not url.strip():
        return False
    
    # Only allow alphanumeric, dots, hyphens, and colons
    url_pattern = r'^[a-zA-Z0-9.-:]+$'
    return bool(re.match(url_pattern, url))

def ping(url):
    """Securely ping a URL"""
    try:
        # Decode URL if encoded
        url = urllib.parse.unquote(url)
        
        # Validate URL to prevent command injection
        if not is_valid_url(url):
            return "Invalid URL format. Only alphanumeric characters, dots, hyphens, and colons are allowed."
        
        # Limit URL length
        if len(url) > 253:
            return "URL too long"
        
        # Build command safely using list (prevents shell injection)
        import platform
        
        if platform.system().lower() == "windows":
            command = ["ping", "-n", "4", url]
        else:
            command = ["ping", "-c", "4", url]
        
        # Execute command with security measures
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False  # Never use shell=True with user input
        )
        
        output = result.stdout + result.stderr
        return f"Ping results for {url}:\\n{output}"
        
    except subprocess.TimeoutExpired:
        return "Ping timeout exceeded"
    except Exception as e:
        return f"Error executing ping: {str(e)}"

if __name__ == "__main__":
    # Test cases
    print("Test 1: Valid domain")
    print(ping("google.com"))
    print("\\n" + "="*50 + "\\n")
    
    print("Test 2: Valid IP address")
    print(ping("8.8.8.8"))
    print("\\n" + "="*50 + "\\n")
    
    print("Test 3: Localhost")
    print(ping("localhost"))
    print("\\n" + "="*50 + "\\n")
    
    print("Test 4: Invalid URL with command injection attempt")
    print(ping("google.com; ls"))
    print("\\n" + "="*50 + "\\n")
    
    print("Test 5: Invalid URL with special characters")
    print(ping("google.com && whoami"))
