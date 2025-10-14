
import hashlib
import hmac
import base64
import re
from typing import Optional

def compute_certificate_hash(cert_bytes: bytes) -> str:
    """\n    Securely computes SHA-256 hash of a certificate\n    \n    Args:\n        cert_bytes: The certificate bytes\n        \n    Returns:\n        Hexadecimal string representation of the hash\n        \n    Raises:\n        ValueError: If cert_bytes is None or empty\n    """
    if not cert_bytes:
        raise ValueError("Certificate bytes cannot be None or empty")
    
    # Use SHA-256 for secure hashing
    hash_obj = hashlib.sha256()
    hash_obj.update(cert_bytes)
    return hash_obj.hexdigest().lower()


def verify_certificate_hash(cert_bytes: bytes, known_hash: str) -> bool:
    """\n    Securely checks if certificate matches known hash using constant-time comparison\n    \n    Args:\n        cert_bytes: The certificate bytes to check\n        known_hash: The known hash to compare against (hexadecimal string)\n        \n    Returns:\n        True if hashes match, False otherwise\n    """
    try:
        if not known_hash:
            raise ValueError("Known hash cannot be None or empty")
        
        # Normalize known hash to lowercase and remove any whitespace/colons
        normalized_known_hash = known_hash.lower()
        normalized_known_hash = re.sub(r'[:\\s]', '', normalized_known_hash)
        
        # Validate known hash format (should be 64 hex characters for SHA-256)
        if not re.match(r'^[0-9a-f]{64}$', normalized_known_hash):
            raise ValueError("Invalid hash format. Expected 64 hexadecimal characters.")
        
        computed_hash = compute_certificate_hash(cert_bytes)
        
        # Use constant-time comparison to prevent timing attacks
        # hmac.compare_digest is the recommended method for constant-time string comparison
        return hmac.compare_digest(computed_hash, normalized_known_hash)
        
    except ValueError as e:
        print(f"Invalid input: {e}")
        return False
    except Exception as e:
        print(f"Error during verification: {e}")
        return False


def load_certificate_from_pem(pem_cert: str) -> bytes:
    """\n    Loads certificate from PEM format string\n    \n    Args:\n        pem_cert: PEM formatted certificate string\n        \n    Returns:\n        Certificate bytes\n        \n    Raises:\n        ValueError: If PEM certificate is invalid\n    """
    if not pem_cert:
        raise ValueError("PEM certificate cannot be None or empty")
    
    # Remove PEM headers and whitespace
    cert_data = pem_cert.replace("-----BEGIN CERTIFICATE-----", "")
    cert_data = cert_data.replace("-----END CERTIFICATE-----", "")
    cert_data = re.sub(r'\\s', '', cert_data)
    
    try:
        decoded = base64.b64decode(cert_data)
        return decoded
    except Exception as e:
        raise ValueError(f"Invalid PEM certificate: {e}")


def main():
    """Main function with test cases"""
    print("=== SSL Certificate Hash Verification Tests ===\\n")
    
    # Test Case 1: Valid certificate with matching hash
    try:
        test_cert1 = b"Test Certificate Data 1"
        hash1 = compute_certificate_hash(test_cert1)
        result1 = verify_certificate_hash(test_cert1, hash1)
        print("Test 1 - Valid certificate with matching hash:")
        print(f"  Computed Hash: {hash1}")
        print(f"  Result: {'PASS (Hashes match)' if result1 else 'FAIL'}")
        print()
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test Case 2: Valid certificate with non-matching hash
    try:
        test_cert2 = b"Test Certificate Data 2"
        wrong_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        result2 = verify_certificate_hash(test_cert2, wrong_hash)
        print("Test 2 - Valid certificate with non-matching hash:")
        print("  Expected: FAIL (Hashes don't match)")
        print(f"  Result: {'PASS (Correctly identified mismatch)' if not result2 else 'FAIL'}")
        print()
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test Case 3: Hash with colons (common format)
    try:
        test_cert3 = b"Test Certificate Data 3"
        hash3 = compute_certificate_hash(test_cert3)
        hash_with_colons = ':'.join(hash3[i:i+2] for i in range(0, len(hash3), 2))
        result3 = verify_certificate_hash(test_cert3, hash_with_colons)
        print("Test 3 - Hash with colon separators:")
        print(f"  Hash format: {hash_with_colons[:20]}...")
        print(f"  Result: {'PASS (Correctly handled format)' if result3 else 'FAIL'}")
        print()
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test Case 4: Invalid hash format
    try:
        test_cert4 = b"Test Certificate Data 4"
        invalid_hash = "invalid_hash_format"
        result4 = verify_certificate_hash(test_cert4, invalid_hash)
        print("Test 4 - Invalid hash format:")
        print("  Expected: FAIL (Invalid format)")
        print(f"  Result: {'PASS (Correctly rejected invalid format)' if not result4 else 'FAIL'}")
        print()
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test Case 5: Empty certificate bytes
    try:
        empty_cert = b""
        some_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        result5 = verify_certificate_hash(empty_cert, some_hash)
        print("Test 5 - Empty certificate:")
        print("  Expected: FAIL (Empty certificate)")
        print(f"  Result: {'PASS (Correctly handled empty input)' if not result5 else 'FAIL'}")
        print()
    except Exception as e:
        print(f"Test 5 handled gracefully: {e}")


if __name__ == "__main__":
    main()
