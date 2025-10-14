
import ssl
import socket
import urllib.request
import urllib.error
from typing import Optional

class Task105:
    
    @staticmethod
    def establish_secure_connection(hostname: str, port: int, message: Optional[str] = None) -> str:
        """\n        Establishes a secure SSL/TLS connection with a remote server\n        :param hostname: The remote server hostname\n        :param port: The remote server port\n        :param message: The message to send (optional)\n        :return: Response from the server or error message\n        """
        if not hostname or not hostname.strip():
            return "Error: Invalid hostname"
        
        if port < 1 or port > 65535:
            return "Error: Invalid port number"
        
        sock = None
        ssl_sock = None
        
        try:
            # Create SSL context with secure settings
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Load default CA certificates for verification
            context.load_default_certs()
            
            # Require certificate verification
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Set secure cipher suites
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            # Create socket and wrap with SSL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 seconds timeout
            
            ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
            ssl_sock.connect((hostname, port))
            
            # Get connection details
            cipher = ssl_sock.cipher()
            protocol = ssl_sock.version()
            
            response = f"Connection successful. Protocol: {protocol}, Cipher: {cipher[0]}\\n"
            
            # Send message if provided
            if message:
                ssl_sock.sendall((message + "\\r\\n").encode('utf-8'))
                
                # Receive response
                data = ssl_sock.recv(4096)
                response += f"Response: {data.decode('utf-8', errors='ignore')}"
            
            return response
            
        except ssl.SSLError as e:
            return f"SSL Error: {str(e)}"
        except socket.timeout:
            return "Error: Connection timeout"
        except Exception as e:
            return f"Error: {str(e)}"
        finally:
            # Clean up resources
            if ssl_sock:
                try:
                    ssl_sock.close()
                except:
                    pass
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    @staticmethod
    def establish_https_connection(url: str) -> str:
        """\n        Simpler method for HTTPS connections using urllib\n        :param url: The HTTPS URL to connect to\n        :return: Response or error message\n        """
        if not url or not url.strip():
            return "Error: Invalid URL"
        
        if not url.startswith("https://"):
            return "Error: Only HTTPS URLs are allowed"
        
        try:
            # Create SSL context with secure settings
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_default_certs()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Create HTTPS handler with secure context
            https_handler = urllib.request.HTTPSHandler(context=context)
            opener = urllib.request.build_opener(https_handler)
            
            # Set timeout
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'SecureClient/1.0')
            
            # Make request
            with opener.open(request, timeout=10) as response:
                data = response.read(10000)  # Limit response size
                content = data.decode('utf-8', errors='ignore')
                
                return f"HTTPS connection successful. Status: {response.status}\\nContent preview: {content[:200]}..."
                
        except urllib.error.URLError as e:
            return f"URL Error: {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"


def main():
    print("=== SSL/TLS Secure Connection Test Cases ===\\n")
    
    task = Task105()
    
    # Test Case 1: Valid HTTPS connection
    print("Test Case 1: Valid HTTPS URL")
    result1 = task.establish_https_connection("https://www.google.com")
    print(result1[:200] + "...\\n")
    
    # Test Case 2: Invalid URL (non-HTTPS)
    print("Test Case 2: Non-HTTPS URL")
    result2 = task.establish_https_connection("http://www.example.com")
    print(result2 + "\\n")
    
    # Test Case 3: Empty hostname
    print("Test Case 3: Empty hostname")
    result3 = task.establish_secure_connection("", 443, "GET / HTTP/1.1")
    print(result3 + "\\n")
    
    # Test Case 4: Invalid port
    print("Test Case 4: Invalid port")
    result4 = task.establish_secure_connection("www.google.com", 99999, "GET / HTTP/1.1")
    print(result4 + "\\n")
    
    # Test Case 5: Null URL
    print("Test Case 5: Null URL")
    result5 = task.establish_https_connection(None)
    print(result5 + "\\n")


if __name__ == "__main__":
    main()
