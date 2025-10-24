
import hashlib
import ssl
import socket
from typing import Optional
import sys


def get_certificate_from_host(hostname: str, port: int = 443, timeout: int = 10) -> Optional[bytes]:
    """\n    Retrieves the SSL certificate from a remote host.\n    \n    Args:\n        hostname: The hostname to connect to\n        port: The port to connect on (default 443)\n        timeout: Connection timeout in seconds\n    \n    Returns:\n        The DER-encoded certificate bytes, or None on error\n    """
    # Input validation: hostname must be non-empty string
    if not hostname or not isinstance(hostname, str):
        print("Error: Invalid hostname", file=sys.stderr)
        return None
    
    # Input validation: port must be in valid range
    if not isinstance(port, int) or port < 1 or port > 65535:
        print("Error: Invalid port number", file=sys.stderr)
        return None
    
    # Input validation: timeout must be positive
    if not isinstance(timeout, int) or timeout < 1:
        print("Error: Invalid timeout value", file=sys.stderr)
        return None
    
    context = None
    sock = None
    ssl_sock = None
    
    try:
        # Create SSL context with secure defaults
        # Enforces TLS 1.2+ and certificate verification to prevent man-in-the-middle attacks
        context = ssl.create_default_context()
        context.check_hostname = True  # Ensures hostname matches certificate (CWE-297)
        context.verify_mode = ssl.CERT_REQUIRED  # Requires valid certificate chain (CWE-295)
        
        # Force minimum TLS 1.2 to prevent downgrade attacks (CWE-327)
        if hasattr(ssl, "TLSVersion"):  # Python 3.10+
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:  # Older Python versions
            context.options |= getattr(ssl, "OP_NO_SSLv2", 0)
            context.options |= getattr(ssl, "OP_NO_SSLv3", 0)
            context.options |= getattr(ssl, "OP_NO_TLSv1", 0)
            context.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
        
        # Create socket with timeout to prevent hanging connections
        sock = socket.create_connection((hostname, port), timeout=timeout)
        
        # Wrap socket with SSL/TLS
        ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
        
        # Get the certificate in DER format (binary)
        cert_der = ssl_sock.getpeercert(binary_form=True)
        
        if cert_der is None:
            print("Error: Failed to retrieve certificate", file=sys.stderr)
            return None
        
        return cert_der
        
    except ssl.SSLError as e:
        print(f"SSL Error: {e}", file=sys.stderr)
        return None
    except socket.timeout:
        print("Error: Connection timeout", file=sys.stderr)
        return None
    except socket.gaierror:
        print("Error: Unable to resolve hostname", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return None
    finally:
        # Clean up resources in reverse order of creation
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def compute_certificate_hash(cert_der: bytes, algorithm: str = "sha256") -> Optional[str]:
    """\n    Computes the hash of a certificate using a strong cryptographic algorithm.\n    \n    Args:\n        cert_der: The DER-encoded certificate bytes\n        algorithm: Hash algorithm to use (sha256 or sha512)\n    \n    Returns:\n        Hex-encoded hash string, or None on error\n    """
    # Input validation: certificate data must be non-empty bytes
    if not cert_der or not isinstance(cert_der, bytes):
        print("Error: Invalid certificate data", file=sys.stderr)
        return None
    
    # Input validation: only allow secure hash algorithms (prevents CWE-327)
    # SHA-256 and SHA-512 are cryptographically secure; MD5 and SHA-1 are forbidden
    allowed_algorithms = {"sha256", "sha512"}
    if algorithm not in allowed_algorithms:
        print(f"Error: Unsupported hash algorithm. Use: {allowed_algorithms}", file=sys.stderr)
        return None
    
    try:
        # Use secure hash algorithm from hashlib
        if algorithm == "sha256":
            hash_obj = hashlib.sha256()
        else:  # sha512
            hash_obj = hashlib.sha512()
        
        hash_obj.update(cert_der)
        return hash_obj.hexdigest()
        
    except Exception as e:
        print(f"Error computing hash: {e}", file=sys.stderr)
        return None


def verify_certificate_hash(hostname: str, known_hash: str, port: int = 443, 
                            algorithm: str = "sha256") -> bool:
    """\n    Verifies that a remote host's SSL certificate matches a known hash.\n    Uses constant-time comparison to prevent timing attacks.\n    \n    Args:\n        hostname: The hostname to verify\n        known_hash: The expected certificate hash (hex string)\n        port: The port to connect on\n        algorithm: Hash algorithm to use\n    \n    Returns:\n        True if certificate matches, False otherwise\n    """
    # Input validation: hostname must be non-empty string
    if not hostname or not isinstance(hostname, str):
        print("Error: Invalid hostname", file=sys.stderr)
        return False
    
    # Input validation: known_hash must be non-empty hex string
    if not known_hash or not isinstance(known_hash, str):
        print("Error: Invalid known hash", file=sys.stderr)
        return False
    
    # Validate known_hash is valid hex
    try:
        bytes.fromhex(known_hash)
    except ValueError:
        print("Error: Known hash must be a valid hex string", file=sys.stderr)
        return False
    
    # Validate expected hash length based on algorithm
    expected_lengths = {"sha256": 64, "sha512": 128}
    if len(known_hash) != expected_lengths.get(algorithm, 0):
        print(f"Error: Hash length mismatch for {algorithm}", file=sys.stderr)
        return False
    
    # Retrieve certificate from remote host
    cert_der = get_certificate_from_host(hostname, port)
    if cert_der is None:
        return False
    
    # Compute hash of retrieved certificate
    computed_hash = compute_certificate_hash(cert_der, algorithm)
    if computed_hash is None:
        return False
    
    # Use constant-time comparison to prevent timing attacks (security best practice)
    # This prevents attackers from determining the hash through timing analysis
    try:
        # Compare both hashes in constant time using hmac.compare_digest
        import hmac
        # Normalize both to lowercase for comparison
        known_lower = known_hash.lower()
        computed_lower = computed_hash.lower()
        
        if hmac.compare_digest(known_lower, computed_lower):
            return True
        else:
            # Do not reveal which part of the hash mismatched (fail closed)
            print("Error: Certificate hash does not match known hash", file=sys.stderr)
            return False
            
    except Exception as e:
        print(f"Error during hash comparison: {e}", file=sys.stderr)
        return False


def main() -> None:
    """\n    Main function with test cases demonstrating certificate hash verification.\n    """
    print("=== SSL Certificate Hash Verification Tests ===\\n")
    
    # Test Case 1: Verify a legitimate certificate (example.com)
    print("Test 1: Retrieve and hash example.com certificate")
    try:
        cert = get_certificate_from_host("example.com", 443)
        if cert:
            hash_val = compute_certificate_hash(cert, "sha256")
            if hash_val:
                print(f"Success: SHA-256 hash = {hash_val}\\n")
            else:
                print("Failed: Could not compute hash\\n")
        else:
            print("Failed: Could not retrieve certificate\\n")
    except Exception as e:
        print(f"Test 1 exception: {e}\\n")
    
    # Test Case 2: Verify with incorrect hash (should fail)
    print("Test 2: Verify example.com with incorrect hash (should fail)")
    incorrect_hash = "0" * 64  # Invalid hash
    result = verify_certificate_hash("example.com", incorrect_hash, 443, "sha256")
    print(f"Result: {'PASS - Correctly rejected' if not result else 'FAIL - Incorrectly accepted'}\\n")
    
    # Test Case 3: Invalid hostname
    print("Test 3: Invalid hostname (should fail gracefully)")
    result = verify_certificate_hash("", "0" * 64, 443, "sha256")
    print(f"Result: {'PASS - Handled error' if not result else 'FAIL'}\\n")
    
    # Test Case 4: Invalid port
    print("Test 4: Invalid port number (should fail)")
    cert = get_certificate_from_host("example.com", 99999)
    print(f"Result: {'PASS - Handled error' if cert is None else 'FAIL'}\\n")
    
    # Test Case 5: Invalid hash algorithm
    print("Test 5: Unsupported hash algorithm (should fail)")
    test_data = b"test certificate data"
    hash_result = compute_certificate_hash(test_data, "md5")  # MD5 is forbidden
    print(f"Result: {'PASS - Rejected insecure algorithm' if hash_result is None else 'FAIL'}\\n")
    
    print("=== All tests completed ===")


if __name__ == "__main__":
    main()
