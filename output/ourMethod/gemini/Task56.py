import os
import time
import base64
import secrets
from typing import Optional

# Requires 'cryptography' package: pip install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

AES_KEY_SIZE = 32  # 256 bits in bytes
GCM_IV_LENGTH = 12  # 96 bits in bytes
GCM_TAG_LENGTH = 16 # 128 bits in bytes

def generate_token(user_id: str, key: bytes, validity_seconds: int) -> Optional[str]:
    """
    Generates a secure authentication token.
    The token contains the user_id and an expiration timestamp, encrypted and authenticated.
    """
    if not user_id:
        return None
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes long.")
    
    try:
        aesgcm = AESGCM(key)
        
        expiration_time = int(time.time()) + validity_seconds
        payload = f"{user_id}:{expiration_time}".encode('utf-8')
        
        iv = secrets.token_bytes(GCM_IV_LENGTH)
        
        ciphertext_with_tag = aesgcm.encrypt(iv, payload, None)
        
        # Concatenate IV and ciphertext (which includes the auth tag)
        token_bytes = iv + ciphertext_with_tag
        
        return base64.urlsafe_b64encode(token_bytes).decode('utf-8')
    except Exception:
        # In a real application, log this error securely
        return None

def validate_token(token: str, key: bytes) -> Optional[str]:
    """
    Validates a token and extracts the user ID if the token is valid and not expired.
    """
    if not token:
        return None
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes long.")

    try:
        aesgcm = AESGCM(key)
        
        token_bytes = base64.urlsafe_b64decode(token)
        
        if len(token_bytes) < GCM_IV_LENGTH + GCM_TAG_LENGTH:
            return None # Not long enough to be a valid token
            
        iv = token_bytes[:GCM_IV_LENGTH]
        ciphertext_with_tag = token_bytes[GCM_IV_LENGTH:]
        
        decrypted_payload = aesgcm.decrypt(iv, ciphertext_with_tag, None).decode('utf-8')
        
        parts = decrypted_payload.split(':', 1)
        if len(parts) != 2:
            return None # Malformed payload

        user_id, expiration_str = parts
        expiration_time = int(expiration_str)
        
        if expiration_time < int(time.time()):
            print("Token expired.")
            return None
            
        return user_id
    except (InvalidTag, ValueError, TypeError):
        # Catches bad tags, bad base64, parsing errors, etc.
        return None

def main():
    """Main function with test cases."""
    # In a real application, this key MUST be loaded from a secure keystore or environment variable.
    # It must NOT be hardcoded.
    secret_key = secrets.token_bytes(AES_KEY_SIZE)
    wrong_key = secrets.token_bytes(AES_KEY_SIZE)
    
    user_id = "user-12345"
    validity_seconds = 3600

    print("--- Test Case 1: Generate and validate a valid token ---")
    token = generate_token(user_id, secret_key, validity_seconds)
    if token:
        print(f"Generated Token: {token}")
        validated_user_id = validate_token(token, secret_key)
        print(f"Validation result: {'SUCCESS' if validated_user_id == user_id else 'FAILURE'}")
        if validated_user_id:
            print(f"Validated User ID: {validated_user_id}")
    else:
        print("Token generation failed.")

    print("\n--- Test Case 2: Validate an expired token ---")
    expired_token = generate_token(user_id, secret_key, -1)
    if expired_token:
        validated_user_id = validate_token(expired_token, secret_key)
        print(f"Validation result: {'SUCCESS (expired as expected)' if not validated_user_id else 'FAILURE'}")
    else:
        print("Expired token generation failed.")

    print("\n--- Test Case 3: Validate a tampered token ---")
    if token:
        # Tamper by flipping a bit in the Base64 representation
        tampered_token = token[:-1] + 'Z'
        print(f"Tampered Token: {tampered_token}")
        validated_user_id = validate_token(tampered_token, secret_key)
        print(f"Validation result: {'SUCCESS (tampering detected)' if not validated_user_id else 'FAILURE'}")

    print("\n--- Test Case 4: Validate with a wrong key ---")
    if token:
        validated_user_id = validate_token(token, wrong_key)
        print(f"Validation result: {'SUCCESS (wrong key detected)' if not validated_user_id else 'FAILURE'}")
        
    print("\n--- Test Case 5: Validate a malformed token ---")
    malformed_token = "this-is-not-a-valid-token"
    validated_user_id = validate_token(malformed_token, secret_key)
    print(f"Validation result: {'SUCCESS (malformed token detected)' if not validated_user_id else 'FAILURE'}")

if __name__ == "__main__":
    main()