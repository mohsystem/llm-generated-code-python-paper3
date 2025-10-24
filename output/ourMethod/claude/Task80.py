
import socket
import ssl
import sys
from typing import Optional

def create_ssl_client_socket(host: str, port: int) -> ssl.SSLSocket:
    """\n    Creates an SSL client socket using IPv6 and TCP protocol.\n    \n    Args:\n        host: The hostname or IPv6 address to connect to\n        port: The port number to connect to\n    \n    Returns:\n        An established SSL socket connection\n    \n    Raises:\n        ValueError: If inputs are invalid\n        socket.error: If connection fails\n        ssl.SSLError: If SSL handshake fails\n    """
    # Input validation - treat all inputs as untrusted
    if not isinstance(host, str) or not host.strip():
        raise ValueError("Host must be a non-empty string")
    
    # Validate port range (1-65535)
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("Port must be an integer between 1 and 65535")
    
    # Sanitize host input - remove leading/trailing whitespace
    host = host.strip()
    
    # Validate host format for IPv6 (basic check)
    # Allow hostname, IPv6 address, or bracketed IPv6
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    
    raw_socket: Optional[socket.socket] = None
    ssl_socket: Optional[ssl.SSLSocket] = None
    
    try:
        # Create SSL context with secure settings
        # Force TLS 1.2 or higher to comply with security requirements
        context = ssl.create_default_context()
        
        # Enable strict hostname verification (CWE-297 mitigation)
        context.check_hostname = True
        
        # Require certificate verification (CWE-295 mitigation)
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Force TLS 1.2+ on all Python versions
        # Python 3.10+ supports TLSVersion enum
        if hasattr(ssl, 'TLSVersion'):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            # For older Python versions, disable weak protocols explicitly
            context.options |= getattr(ssl, 'OP_NO_SSLv2', 0)
            context.options |= getattr(ssl, 'OP_NO_SSLv3', 0)
            context.options |= getattr(ssl, 'OP_NO_TLSv1', 0)
            context.options |= getattr(ssl, 'OP_NO_TLSv1_1', 0)
        
        # Create raw TCP socket with IPv6 and TCP protocol
        # AF_INET6 for IPv6, SOCK_STREAM for TCP
        raw_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        
        # Set socket timeout to prevent indefinite blocking
        raw_socket.settimeout(30.0)
        
        # Connect to the remote host
        # Use getaddrinfo to resolve hostname to IPv6 address if needed
        try:
            # Resolve hostname to IPv6 addresses
            addr_info = socket.getaddrinfo(
                host, 
                port, 
                socket.AF_INET6, 
                socket.SOCK_STREAM
            )
            
            if not addr_info:
                raise socket.error("Unable to resolve host to IPv6 address")
            
            # Use the first resolved address
            target_addr = addr_info[0][4]
            
        except socket.gaierror as e:
            raise socket.error(f"DNS resolution failed: {e}")
        
        # Establish TCP connection
        raw_socket.connect(target_addr)
        
        # Wrap socket with SSL/TLS
        # server_hostname is required for proper certificate validation (CWE-297)
        ssl_socket = context.wrap_socket(
            raw_socket,
            server_hostname=host,
            do_handshake_on_connect=True
        )
        
        # Verify the SSL certificate chain was validated
        # get_verified_chain() raises SSLError if verification failed
        if hasattr(ssl_socket, 'get_verified_chain'):
            # Python 3.13+ has this method
            ssl_socket.get_verified_chain()
        
        # Additional certificate validation check
        peer_cert = ssl_socket.getpeercert()
        if not peer_cert:
            raise ssl.SSLError("No peer certificate received")
        
        # Return the established SSL socket
        return ssl_socket
        
    except (socket.error, ssl.SSLError, ValueError) as e:
        # Clean up resources on failure
        if ssl_socket is not None:
            try:
                ssl_socket.close()
            except Exception:
                pass
        elif raw_socket is not None:
            try:
                raw_socket.close()
            except Exception:
                pass
        
        # Re-raise the exception with clear error message
        raise type(e)(f"Failed to create SSL client socket: {e}")
    
    except Exception as e:
        # Catch any unexpected exceptions and clean up
        if ssl_socket is not None:
            try:
                ssl_socket.close()
            except Exception:
                pass
        elif raw_socket is not None:
            try:
                raw_socket.close()
            except Exception:
                pass
        
        raise RuntimeError(f"Unexpected error creating SSL socket: {e}")


def main() -> None:
    """Main function with test cases"""
    
    print("SSL IPv6 Client Socket Test Cases")
    print("=" * 50)
    
    # Test case 1: Valid connection to public IPv6 HTTPS server
    print("\\nTest 1: Connect to google.com on port 443")
    try:
        sock = create_ssl_client_socket("google.com", 443)
        print(f"✓ Success: Connected to {sock.getpeername()}")
        print(f"  SSL Version: {sock.version()}")
        sock.close()
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test case 2: Invalid port (out of range)
    print("\\nTest 2: Invalid port number (70000)")
    try:
        sock = create_ssl_client_socket("google.com", 70000)
        sock.close()
        print("✗ Should have raised ValueError")
    except ValueError as e:
        print(f"✓ Correctly raised ValueError: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    
    # Test case 3: Invalid port (zero)
    print("\\nTest 3: Invalid port number (0)")
    try:
        sock = create_ssl_client_socket("google.com", 0)
        sock.close()
        print("✗ Should have raised ValueError")
    except ValueError as e:
        print(f"✓ Correctly raised ValueError: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    
    # Test case 4: Empty host string
    print("\\nTest 4: Empty host string")
    try:
        sock = create_ssl_client_socket("", 443)
        sock.close()
        print("✗ Should have raised ValueError")
    except ValueError as e:
        print(f"✓ Correctly raised ValueError: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    
    # Test case 5: Invalid host that cannot resolve
    print("\\nTest 5: Non-existent hostname")
    try:
        sock = create_ssl_client_socket("nonexistent-host-12345.invalid", 443)
        sock.close()
        print("✗ Should have raised socket.error")
    except socket.error as e:
        print(f"✓ Correctly raised socket.error: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    
    print("\\n" + "=" * 50)
    print("Test cases completed")


if __name__ == "__main__":
    main()
