
import re
import socket
import subprocess
import shlex

class Lse113:
    VALID_HOSTNAME = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$'
    )
    VALID_IP = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    @staticmethod
    def ping(url):
        """Securely ping a URL without command injection vulnerability"""
        # Input validation
        if not url or not isinstance(url, str):
            return "Error: Invalid input - URL cannot be empty"
        
        url = url.strip()
        
        # Remove protocol if present
        url = re.sub(r'^https?://', '', url)
        # Remove path if present
        url = url.split('/')[0]
        
        # Validate hostname or IP
        if not (Lse113.VALID_HOSTNAME.match(url) or Lse113.VALID_IP.match(url)):
            return "Error: Invalid hostname or IP address format"
        
        try:
            # Method 1: Use socket for quick check (safer than subprocess)
            socket.setdefaulttimeout(5)
            socket.gethostbyname(url)
            
            # Method 2: If system ping is required, use subprocess with list arguments
            # NEVER use shell=True with user input
            import platform
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            
            # Use list of arguments to prevent command injection
            command = ['ping', param, '1', '-W', '5', url]
            
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if result.returncode == 0:
                return f"URL {url} is alive"
            else:
                return f"URL {url} is not alive"
                
        except socket.gaierror:
            return f"Error: Unknown host - {url}"
        except subprocess.TimeoutExpired:
            return f"Error: Timeout while pinging {url}"
        except Exception as e:
            return f"Error: Cannot reach host - {url}"

def main():
    # Test cases
    print("Test 1:", Lse113.ping("8.8.8.8"))
    print("Test 2:", Lse113.ping("google.com"))
    print("Test 3:", Lse113.ping("invalid..host"))
    print("Test 4:", Lse113.ping("; rm -rf /"))
    print("Test 5:", Lse113.ping(""))

if __name__ == "__main__":
    main()
