
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def generate_rsa_private_key_openssh(key_size):
    try:
        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Serialize to OpenSSH format
        openssh_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return openssh_key.decode('utf-8')
        
    except Exception as e:
        return f"Error generating key: {str(e)}"

def main():
    print("Test Case 1: Generate 2048-bit RSA key")
    key1 = generate_rsa_private_key_openssh(2048)
    print(key1[:200] + "...\\n")
    
    print("Test Case 2: Generate 1024-bit RSA key")
    key2 = generate_rsa_private_key_openssh(1024)
    print(key2[:200] + "...\\n")
    
    print("Test Case 3: Generate 2048-bit RSA key (second instance)")
    key3 = generate_rsa_private_key_openssh(2048)
    print(key3[:200] + "...\\n")
    
    print("Test Case 4: Generate 3072-bit RSA key")
    key4 = generate_rsa_private_key_openssh(3072)
    print(key4[:200] + "...\\n")
    
    print("Test Case 5: Generate 4096-bit RSA key")
    key5 = generate_rsa_private_key_openssh(4096)
    print(key5[:200] + "...\\n")

if __name__ == "__main__":
    main()
