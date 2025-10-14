
import ssl
import socket

class Task105:
    @staticmethod
    def establish_secure_connection(host, port):
        """Establish a secure SSL/TLS connection to a remote server"""
        # Create SSL context with secure defaults
        context = ssl.create_default_context()
        
        # Set minimum TLS version to TLSv1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Disable weak ciphers
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS')
        
        # Create socket and wrap with SSL
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))
        
        return ssl_sock
    
    @staticmethod
    def send_request(host, port, request):
        """Send a request over SSL/TLS connection and receive response"""
        try:
            ssl_sock = Task105.establish_secure_connection(host, port)
            
            # Send request
            ssl_sock.sendall(request.encode('utf-8'))
            
            # Receive response
            response = b""
            while len(response) < 10000:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\\r\\n\\r\\n" in response:
                    break
            
            ssl_sock.close()
            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            raise Exception(f"Connection failed: {str(e)}")

def main():
    print("SSL/TLS Secure Connection Test Cases:\\n")
    
    # Test case 1: HTTPS connection to Google
    try:
        print("Test 1: Connecting to www.google.com:443")
        response = Task105.send_request("www.google.com", 443, 
            "GET / HTTP/1.1\\r\\nHost: www.google.com\\r\\n\\r\\n")
        print(f"Connection successful! Response length: {len(response)}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: HTTPS connection to GitHub
    try:
        print("\\nTest 2: Connecting to github.com:443")
        response = Task105.send_request("github.com", 443, 
            "GET / HTTP/1.1\\r\\nHost: github.com\\r\\n\\r\\n")
        print(f"Connection successful! Response length: {len(response)}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: HTTPS connection to Amazon
    try:
        print("\\nTest 3: Connecting to www.amazon.com:443")
        response = Task105.send_request("www.amazon.com", 443, 
            "GET / HTTP/1.1\\r\\nHost: www.amazon.com\\r\\n\\r\\n")
        print(f"Connection successful! Response length: {len(response)}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: HTTPS connection to Microsoft
    try:
        print("\\nTest 4: Connecting to www.microsoft.com:443")
        response = Task105.send_request("www.microsoft.com", 443, 
            "GET / HTTP/1.1\\r\\nHost: www.microsoft.com\\r\\n\\r\\n")
        print(f"Connection successful! Response length: {len(response)}")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: Invalid host test
    try:
        print("\\nTest 5: Connecting to invalid.host.example:443")
        response = Task105.send_request("invalid.host.example", 443, 
            "GET / HTTP/1.1\\r\\nHost: invalid.host.example\\r\\n\\r\\n")
        print(f"Connection successful! Response length: {len(response)}")
    except Exception as e:
        print(f"Test 5 failed (expected): {e}")

if __name__ == "__main__":
    main()
