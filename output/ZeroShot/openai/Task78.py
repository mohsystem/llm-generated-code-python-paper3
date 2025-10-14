# Requires the 'cryptography' package: pip install cryptography
from typing import Optional

def generate_openssh_rsa_private_key(key_size: int = 3072, comment: Optional[str] = None) -> str:
    try:
        if key_size < 2048 or key_size > 16384:
            raise ValueError("key_size must be between 2048 and 16384 bits")
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        # 'comment' embedding for OpenSSH private keys is not supported by cryptography as of now.
        return pem.decode("utf-8")
    except Exception as e:
        raise RuntimeError(f"Key generation failed: {e}")

if __name__ == "__main__":
    # 5 test cases
    print(generate_openssh_rsa_private_key(3072, "user1@example.com"))
    print(generate_openssh_rsa_private_key(4096, "Task78-key-1"))
    print(generate_openssh_rsa_private_key(3072, "no comment"))
    print(generate_openssh_rsa_private_key(2048, "legacy-compat"))
    print(generate_openssh_rsa_private_key(3072, "another-key"))