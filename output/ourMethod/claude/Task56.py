
import secrets
import base64
import hashlib
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

TOKEN_LENGTH = 32
SALT_LENGTH = 16
PBKDF2_ITERATIONS = 210000
KEY_LENGTH = 32


def generate_token() -> str:
    """Generate a cryptographically secure random token."""
    token_bytes = secrets.token_bytes(TOKEN_LENGTH)
    return base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')


def hash_token(token: str) -> str:
    """Hash a token with PBKDF2-HMAC-SHA256 and a unique salt."""
    if not token:
        raise ValueError("Token cannot be empty")
    
    salt = secrets.token_bytes(SALT_LENGTH)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    
    token_bytes = token.encode('utf-8')
    hash_value = kdf.derive(token_bytes)
    
    combined = salt + hash_value
    return base64.b64encode(combined).decode('utf-8')


def verify_token(token: str, stored_hash: str) -> bool:
    """Verify a token against a stored hash using constant-time comparison."""
    if not token or not stored_hash:
        return False
    
    try:
        combined = base64.b64decode(stored_hash)
        
        if len(combined) < SALT_LENGTH:
            return False
        
        salt = combined[:SALT_LENGTH]
        hash_value = combined[SALT_LENGTH:]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        token_bytes = token.encode('utf-8')
        test_hash = kdf.derive(token_bytes)
        
        return secrets.compare_digest(hash_value, test_hash)
    except Exception:
        return False


def main():
    print("Test Case 1: Generate token")
    token1 = generate_token()
    print(f"Generated token: {token1}")
    print(f"Token length valid: {len(token1) > 0}")
    
    print("\\nTest Case 2: Hash token")
    hash1 = hash_token(token1)
    print(f"Hashed token stored (length): {len(hash1)}")
    
    print("\\nTest Case 3: Verify correct token")
    verified = verify_token(token1, hash1)
    print(f"Token verified: {verified}")
    
    print("\\nTest Case 4: Verify incorrect token")
    token2 = generate_token()
    not_verified = verify_token(token2, hash1)
    print(f"Different token rejected: {not not_verified}")
    
    print("\\nTest Case 5: Multiple unique tokens")
    token3 = generate_token()
    token4 = generate_token()
    token5 = generate_token()
    all_unique = token3 != token4 and token3 != token5 and token4 != token5
    print(f"All tokens unique: {all_unique}")


if __name__ == "__main__":
    main()
