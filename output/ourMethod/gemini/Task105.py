import ssl
import socket
from typing import Optional, Tuple, Any

def create_secure_context() -> ssl.SSLContext:
    """
    Creates and configures a secure SSL context.
    
    This context is configured to:
    - Trust the system's default certificate authorities.
    - Require and validate server certificates.
    - Verify that the server's hostname matches its certificate.
    - Use a minimum of TLS 1.2, disabling older, insecure protocols.
    """
    # Use create_default_context() as a secure baseline. It loads default CAs,
    # enables hostname checking, and sets secure default options.
    context = ssl.create_default_context()

    # Enforce certificate validation and hostname checking. While these are defaults
    # in create_default_context(), being explicit makes the security posture clear.
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    # Enforce modern TLS versions, compliant with security best practices.
    # For Python 3.10 and newer, we can use the TLSVersion enum.
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:  # For older Python versions, we disable protocols via bitmask options.
        # This explicitly disables SSLv2, SSLv3, TLSv1.0, and TLSv1.1.
        context.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        context.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        context.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        context.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    
    return context

def establish_secure_connection(hostname: str, port: int = 443) -> Optional[Tuple[str, Tuple[Any, ...]]]:
    """
    Establishes a secure SSL/TLS connection to a given host and port.

    Args:
        hostname: The hostname of the server to connect to.
        port: The port of the server (default is 443 for HTTPS).

    Returns:
        A tuple containing the TLS protocol version and cipher details,
        or None if the connection failed due to a security or network issue.
    """
    if not hostname:
        print("Error: Hostname cannot be empty.")
        return None

    context = create_secure_context()
    
    try:
        # Create a TCP socket and establish a connection using a context manager.
        with socket.create_connection((hostname, port), timeout=10) as sock:
            # Wrap the socket with the secure SSL context. The 'server_hostname'
            # argument is crucial for SNI and proper hostname verification.
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"Successfully established secure connection to {hostname}:{port}.")
                
                # Retrieve and return connection details.
                protocol_version = ssock.version() or "N/A"
                cipher_info = ssock.cipher()
                
                if not cipher_info:
                    cipher_info = ("N/A", "N/A", 0)
                
                return protocol_version, cipher_info

    except ssl.SSLCertVerificationError as e:
        print(f"Connection to {hostname} failed: Certificate verification error. "
              f"Reason: {e.reason}")
    except ssl.SSLError as e:
        print(f"Connection to {hostname} failed: An SSL error occurred. "
              f"Error: {e}")
    except socket.gaierror:
        print(f"Connection to {hostname} failed: Hostname could not be resolved.")
    except socket.timeout:
        print(f"Connection to {hostname} failed: The connection timed out.")
    except ConnectionRefusedError:
        print(f"Connection to {hostname} failed: The server refused the connection.")
    except OSError as e:
        print(f"Connection to {hostname} failed: An OS-level error occurred. "
              f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while connecting to {hostname}: {e}")

    return None

def main() -> None:
    """
    Main function to run test cases for establishing secure connections.
    """
    print("--- Running SSL/TLS Connection Tests ---")

    # Test cases:
    # 1. A known good, secure site (Google).
    # 2. Another known good, secure site (Python.org).
    # 3. A site with an expired certificate (should fail certificate validation).
    # 4. A site with a self-signed certificate (should fail certificate validation).
    # 5. A non-existent host (should fail hostname resolution).
    test_hosts = [
        ("www.google.com", 443),
        ("www.python.org", 443),
        ("expired.badssl.com", 443),
        ("self-signed.badssl.com", 443),
        ("this-is-not-a-real-domain.invalid", 443),
    ]

    for host, port in test_hosts:
        print("\n" + "=" * 50)
        print(f"Attempting to connect to: {host}:{port}")
        print("=" * 50)
        
        result = establish_secure_connection(host, port)
        
        if result:
            protocol, cipher_info_tuple = result
            cipher_name, cipher_protocol, key_bits = cipher_info_tuple
            print("\n[SUCCESS] Connection established securely.")
            print(f"  - TLS Protocol Version: {protocol}")
            print(f"  - Cipher Suite: {cipher_name}")
            print(f"  - Cipher Protocol: {cipher_protocol}")
            print(f"  - Key Bits: {key_bits}")
        else:
            print("\n[FAILURE] Connection failed or was insecure. "
                  "This may be expected for certain test cases.")
        
        print("=" * 50)

    print("\n--- All tests completed. ---")


if __name__ == "__main__":
    main()