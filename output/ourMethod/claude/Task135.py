
import hmac
import hashlib
import secrets
import base64
import time
from typing import Dict, Optional, Tuple

TOKEN_LENGTH = 32
TOKEN_EXPIRY_MS = 3600000  # 1 hour
token_store: Dict[str, Tuple[str, int]] = {}
hmac_key = secrets.token_bytes(32)


def generate_csrf_token(session_id: str) -> str:
    if not session_id or not session_id.strip():
        raise ValueError("Session ID cannot be null or empty")
    
    random_bytes = secrets.token_bytes(TOKEN_LENGTH)
    token = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
    
    expiry_time = int(time.time() * 1000) + TOKEN_EXPIRY_MS
    token_store[token] = (session_id, expiry_time)
    
    clean_expired_tokens()
    return token


def validate_csrf_token(token: str, session_id: str) -> bool:
    if not token or not token.strip():
        return False
    if not session_id or not session_id.strip():
        return False
    
    data = token_store.get(token)
    if data is None:
        return False
    
    stored_session_id, expiry_time = data
    current_time = int(time.time() * 1000)
    
    if current_time > expiry_time:
        token_store.pop(token, None)
        return False
    
    is_valid = constant_time_equals(stored_session_id, session_id)
    if is_valid:
        token_store.pop(token, None)
    
    return is_valid


def generate_hmac_token(session_id: str, action: str) -> str:
    if not session_id or not session_id.strip():
        raise ValueError("Session ID cannot be null or empty")
    if not action or not action.strip():
        raise ValueError("Action cannot be null or empty")
    
    timestamp = int(time.time() * 1000)
    message = f"{session_id}:{action}:{timestamp}"
    
    signature = hmac.new(
        hmac_key,
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    return f"{signature_b64}:{timestamp}"


def validate_hmac_token(token: str, session_id: str, action: str) -> bool:
    if not token or not token.strip():
        return False
    if not session_id or not session_id.strip():
        return False
    if not action or not action.strip():
        return False
    
    parts = token.split(':')
    if len(parts) != 2:
        return False
    
    try:
        provided_signature = parts[0]
        timestamp = int(parts[1])
        
        current_time = int(time.time() * 1000)
        if current_time - timestamp > TOKEN_EXPIRY_MS:
            return False
        
        message = f"{session_id}:{action}:{timestamp}"
        expected_signature_bytes = hmac.new(
            hmac_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        expected_signature = base64.urlsafe_b64encode(expected_signature_bytes).decode('utf-8').rstrip('=')
        
        return constant_time_equals(provided_signature, expected_signature)
    except (ValueError, IndexError):
        return False


def constant_time_equals(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


def clean_expired_tokens() -> None:
    current_time = int(time.time() * 1000)
    expired_tokens = [token for token, (_, expiry) in token_store.items() if current_time > expiry]
    for token in expired_tokens:
        token_store.pop(token, None)


def main() -> None:
    print("CSRF Protection Implementation Test Cases\\n")
    
    # Test Case 1: Generate and validate token
    print("Test 1: Generate and validate CSRF token")
    session_id1 = "session123"
    token1 = generate_csrf_token(session_id1)
    print(f"Generated token: {token1}")
    valid1 = validate_csrf_token(token1, session_id1)
    print(f"Validation result: {valid1}")
    print()
    
    # Test Case 2: Invalid session ID
    print("Test 2: Validate with wrong session ID")
    session_id2 = "session456"
    token2 = generate_csrf_token(session_id2)
    valid2 = validate_csrf_token(token2, "wrongSession")
    print(f"Validation result (should be False): {valid2}")
    print()
    
    # Test Case 3: Token reuse protection
    print("Test 3: Token reuse protection")
    session_id3 = "session789"
    token3 = generate_csrf_token(session_id3)
    first_use = validate_csrf_token(token3, session_id3)
    second_use = validate_csrf_token(token3, session_id3)
    print(f"First use: {first_use}")
    print(f"Second use (should be False): {second_use}")
    print()
    
    # Test Case 4: HMAC-based token generation and validation
    print("Test 4: HMAC-based CSRF token")
    session_id4 = "sessionABC"
    action4 = "deleteAccount"
    hmac_token = generate_hmac_token(session_id4, action4)
    print(f"Generated HMAC token: {hmac_token}")
    valid_hmac = validate_hmac_token(hmac_token, session_id4, action4)
    print(f"HMAC validation result: {valid_hmac}")
    print()
    
    # Test Case 5: HMAC token with wrong action
    print("Test 5: HMAC token with wrong action")
    session_id5 = "sessionXYZ"
    action5 = "updateProfile"
    hmac_token5 = generate_hmac_token(session_id5, action5)
    valid_hmac5 = validate_hmac_token(hmac_token5, session_id5, "wrongAction")
    print(f"HMAC validation result (should be False): {valid_hmac5}")


if __name__ == "__main__":
    main()
