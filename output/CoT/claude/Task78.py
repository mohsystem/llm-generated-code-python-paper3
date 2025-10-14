
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sys

def generate_rsa_private_key_openssh(key_size):
    """\n    Generate RSA private key and export in OpenSSH format\n    \n    Args:\n        key_size: Size of the RSA key in bits (minimum 2048)\n    \n    Returns:\n        String containing the private key in OpenSSH format\n    """
    try:
        # Validate minimum key size for security
        if key_size < 2048:
            raise ValueError("Key size must be at least 2048 bits for security")
        
        # Generate RSA private key with secure parameters
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard secure public exponent
            key_size=key_size,
            backend=default_backend()
        )
        
        # Serialize private key to OpenSSH format
        openssh_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return openssh_private_key.decode('utf-8')
        
    except ValueError as e:
        raise ValueError(f"Invalid parameter: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Error generating RSA key: {str(e)}")


if __name__ == "__main__":
    print("=== RSA Private Key Generator (OpenSSH Format) ===\\n")
    
    # Test case 1: 2048-bit key (minimum secure)
    print("Test Case 1: Generate 2048-bit RSA key")
    try:
        key1 = generate_rsa_private_key_openssh(2048)
        print(f"Success - Key length: {len(key1)} characters")
        print(key1[:200] + "...\\n")
    except Exception as e:
        print(f"Error: {str(e)}\\n")
    
    # Test case 2: 4096-bit key (highly secure)
    print("Test Case 2: Generate 4096-bit RSA key")
    try:
        key2 = generate_rsa_private_key_openssh(4096)
        print(f"Success - Key length: {len(key2)} characters")
        print(key2[:200] + "...\\n")
    except Exception as e:
        print(f"Error: {str(e)}\\n")
    
    # Test case 3: Invalid key size (should fail)
    print("Test Case 3: Attempt 1024-bit key (insecure, should fail)")
    try:
        key3 = generate_rsa_private_key_openssh(1024)
        print(f"Generated: {key3[:100]}...\\n")
    except Exception as e:
        print(f"Expected Error: {str(e)}\\n")
    
    # Test case 4: 3072-bit key
    print("Test Case 4: Generate 3072-bit RSA key")
    try:
        key4 = generate_rsa_private_key_openssh(3072)
        print(f"Success - Key length: {len(key4)} characters")
        print(key4[:200] + "...\\n")
    except Exception as e:
        print(f"Error: {str(e)}\\n")
    
    # Test case 5: Standard 2048-bit with full output
    print("Test Case 5: Generate 2048-bit key with full display")
    try:
        key5 = generate_rsa_private_key_openssh(2048)
        print(f"Full key generated:\\n{key5}")
    except Exception as e:
        print(f"Error: {str(e)}\\n")
