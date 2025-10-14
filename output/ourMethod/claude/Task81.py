
import hashlib
import hmac
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone


def verify_certificate_hash(certificate_bytes: bytes, expected_hash_hex: str) -> bool:
    """\n    Verifies if the certificate hash matches the expected hash using constant-time comparison.\n    \n    Args:\n        certificate_bytes: The certificate bytes to verify\n        expected_hash_hex: The expected SHA-256 hash in hexadecimal format\n        \n    Returns:\n        True if the hash matches, False otherwise\n    """
    if not certificate_bytes or len(certificate_bytes) == 0:
        return False
    
    if not expected_hash_hex or len(expected_hash_hex) == 0:
        return False
    
    # Validate hex format and length
    if not all(c in '0123456789abcdefABCDEF' for c in expected_hash_hex):
        return False
    
    if len(expected_hash_hex) != 64:
        return False
    
    try:
        # Parse certificate
        cert = x509.load_pem_x509_certificate(certificate_bytes, default_backend())
        
        # Check certificate validity period
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False
        
        # Compute SHA-256 hash
        cert_der = cert.public_bytes(encoding=x509.Encoding.DER)
        cert_hash = hashlib.sha256(cert_der).digest()
        
        # Convert to hex
        actual_hash_hex = cert_hash.hex()
        
        # Constant-time comparison
        return constant_time_equals(actual_hash_hex.lower(), expected_hash_hex.lower())
        
    except Exception:
        return False


def constant_time_equals(a: str, b: str) -> bool:
    """\n    Constant-time string comparison to prevent timing attacks.\n    """
    if a is None or b is None:
        return False
    
    a_bytes = a.encode('utf-8')
    b_bytes = b.encode('utf-8')
    
    return hmac.compare_digest(a_bytes, b_bytes)


def load_certificate_from_file(file_path: str) -> bytes:
    """\n    Loads a certificate from a file path.\n    """
    if not file_path or len(file_path) == 0:
        raise ValueError("File path cannot be empty")
    
    import os
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Certificate file not found: {file_path}")
    
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    
    file_size = os.path.getsize(file_path)
    if file_size > 10 * 1024 * 1024:  # 10MB limit
        raise ValueError("Certificate file too large")
    
    with open(file_path, 'rb') as f:
        return f.read()


def main() -> None:
    # Test case 1: Valid certificate format but non-matching hash
    print("Test Case 1: Valid certificate with non-matching hash")
    test_cert1 = b"""-----BEGIN CERTIFICATE-----\nMIICpDCCAYwCCQDU+pQ3ZUD30jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\nb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD\nVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7\nVJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1+fWIcPm9z4Hj1C4C1eFpQ2PQmXYLX3z1k\n-----END CERTIFICATE-----"""
    
    expected_hash1 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    result1 = verify_certificate_hash(test_cert1, expected_hash1)
    print(f"Result: {result1} (Expected: False - invalid cert format)\\n")
    
    # Test case 2: Invalid hex format
    print("Test Case 2: Invalid hex format in expected hash")
    cert_bytes2 = b"test"
    invalid_hash = "ZZZZZZ"
    result2 = verify_certificate_hash(cert_bytes2, invalid_hash)
    print(f"Result: {result2} (Expected: False - invalid hex)\\n")
    
    # Test case 3: Empty certificate
    print("Test Case 3: Empty certificate bytes")
    result3 = verify_certificate_hash(b"", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
    print(f"Result: {result3} (Expected: False - empty input)\\n")
    
    # Test case 4: None expected hash
    print("Test Case 4: None expected hash")
    cert_bytes4 = b"test"
    result4 = verify_certificate_hash(cert_bytes4, None)
    print(f"Result: {result4} (Expected: False - None hash)\\n")
    
    # Test case 5: Hash with wrong length
    print("Test Case 5: Hash with incorrect length")
    cert_bytes5 = b"test"
    short_hash = "abcdef"
    result5 = verify_certificate_hash(cert_bytes5, short_hash)
    print(f"Result: {result5} (Expected: False - wrong length)\\n")


if __name__ == "__main__":
    main()
