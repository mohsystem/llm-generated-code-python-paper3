
import ssl
import socket
import sys

class Task105:
    @staticmethod
    def create_secure_connection(host, port):
        context = ssl.create_default_context()
        sock = socket.create_connection((host, port))
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        return ssl_sock
    
    @staticmethod
    def send_https_request(host, port, request):
        try:
            ssl_sock = Task105.create_secure_connection(host, port)
            
            request_str = f"{request}\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n"
            ssl_sock.sendall(request_str.encode())
            
            response = b""
            while True:
                data = ssl_sock.recv(4096)
                if not data:
                    break
                response += data
                if len(response) > 10000:
                    break
            
            ssl_sock.close()
            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def create_secure_server(port):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', port))
        server_socket.listen(5)
        return context.wrap_socket(server_socket, server_side=True)
    
    @staticmethod
    def get_connection_info(host, port):
        try:
            ssl_sock = Task105.create_secure_connection(host, port)
            cipher = ssl_sock.cipher()
            version = ssl_sock.version()
            
            info = f"Protocol: {version}\\n"
            info += f"Cipher Suite: {cipher[0]}\\n"
            info += f"Cipher Bits: {cipher[2]}\\n"
            
            ssl_sock.close()
            return info
        except Exception as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def verify_connection(host, port):
        try:
            ssl_sock = Task105.create_secure_connection(host, port)
            ssl_sock.close()
            return True
        except Exception:
            return False

def main():
    print("Test Case 1: Verify secure connection to google.com:443")
    try:
        result = Task105.verify_connection("google.com", 443)
        print(f"Connection verified: {result}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    print("\\nTest Case 2: Get connection info for google.com:443")
    try:
        info = Task105.get_connection_info("google.com", 443)
        print(info)
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    print("\\nTest Case 3: Send HTTPS request to example.com:443")
    try:
        response = Task105.send_https_request("example.com", 443, "GET / HTTP/1.1")
        print(f"Response received (first 200 chars): {response[:200]}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    print("\\nTest Case 4: Verify connection to httpbin.org:443")
    try:
        result = Task105.verify_connection("httpbin.org", 443)
        print(f"Connection verified: {result}")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    print("\\nTest Case 5: Test invalid connection")
    try:
        result = Task105.verify_connection("invalid-host-12345.com", 443)
        print(f"Connection verified: {result}")
    except Exception as e:
        print(f"Test 5 - Expected failure: {e}")

if __name__ == "__main__":
    main()
