
import socket
import ssl
import sys

def create_ssl_client_socket(host, port):
    if not host or not isinstance(host, str) or not host.strip():
        raise ValueError("Host cannot be null or empty")
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535")
    
    try:
        # Create SSL context with secure defaults
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Load default CA certificates for verification
        context.load_default_certs()
        
        # Enable hostname verification
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Create IPv6 socket
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        
        # Wrap socket with SSL
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        
        # Connect to the specified host and port
        ssl_sock.connect((host, port))
        
        return ssl_sock
        
    except socket.gaierror:
        # If IPv6 fails, try IPv4
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            return ssl_sock
        except Exception as e:
            raise Exception(f"Connection failed: {str(e)}")
    except Exception as e:
        raise Exception(f"SSL connection failed: {str(e)}")

if __name__ == "__main__":
    # Test cases
    test_cases = [
        ("www.google.com", 443),
        ("www.github.com", 443),
        ("www.amazon.com", 443),
        ("www.microsoft.com", 443),
        ("www.cloudflare.com", 443)
    ]
    
    for host, port in test_cases:
        try:
            print(f"Connecting to {host}:{port}")
            
            ssl_socket = create_ssl_client_socket(host, port)
            
            if ssl_socket:
                print(f"Successfully connected to {host}:{port}")
                print(f"Protocol: {ssl_socket.version()}")
                print(f"Cipher: {ssl_socket.cipher()[0]}")
                ssl_socket.close()
        except Exception as e:
            print(f"Failed to connect: {str(e)}")
        print("---")
