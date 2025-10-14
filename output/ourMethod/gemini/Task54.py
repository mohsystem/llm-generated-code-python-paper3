import secrets
import time
from typing import Dict, Any

# In-memory store for OTPs. In a real application, use a database or a cache like Redis.
OTP_STORE: Dict[str, Dict[str, Any]] = {}
OTP_LENGTH = 6
OTP_VALIDITY_SECONDS = 60

def generate_otp(username: str) -> str:
    """
    Generates a random One-Time Password (OTP) for a user.
    In a real application, this would also trigger sending the OTP to the user.
    """
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username must be a non-empty string.")

    max_val = 10**OTP_LENGTH
    otp_int = secrets.randbelow(max_val)
    otp_str = f"{otp_int:0{OTP_LENGTH}d}"

    OTP_STORE[username] = {
        'otp': otp_str,
        'timestamp': time.monotonic()
    }
    return otp_str

def verify_otp(username: str, submitted_otp: str) -> bool:
    """
    Verifies the submitted OTP for a given user.
    Atomically retrieves and removes the OTP to prevent reuse.
    """
    if not isinstance(username, str) or not isinstance(submitted_otp, str):
        return False
        
    otp_data = OTP_STORE.pop(username, None)

    if otp_data is None:
        return False

    # Check for expiration
    if time.monotonic() - otp_data['timestamp'] > OTP_VALIDITY_SECONDS:
        return False

    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(otp_data['otp'], submitted_otp)

def main():
    """Main function with test cases."""
    test_user = "testuser@example.com"

    # Test Case 1: Successful verification
    print("--- Test Case 1: Successful Verification ---")
    otp1 = generate_otp(test_user)
    print(f"Generated OTP for {test_user}: {otp1} (for testing)")
    is_valid1 = verify_otp(test_user, otp1)
    print(f"Verification successful: {is_valid1}\n")

    # Test Case 2: Failed verification due to incorrect OTP
    print("--- Test Case 2: Incorrect OTP ---")
    otp2 = generate_otp(test_user)
    print(f"Generated OTP for {test_user}: {otp2} (for testing)")
    wrong_otp = "000000"
    is_valid2 = verify_otp(test_user, wrong_otp)
    print(f"Verification with wrong OTP ({wrong_otp}) successful: {is_valid2}\n")

    # Test Case 3: Failed verification due to reuse
    print("--- Test Case 3: OTP Reuse ---")
    otp3 = generate_otp(test_user)
    print(f"Generated OTP for {test_user}: {otp3} (for testing)")
    verify_otp(test_user, otp3)  # First, successful use
    print(f"Attempting to reuse OTP {otp3}")
    is_valid3 = verify_otp(test_user, otp3)  # Second, failed use
    print(f"Second verification successful: {is_valid3}\n")

    # Test Case 4: Failed verification due to expiration
    print("--- Test Case 4: Expired OTP ---")
    otp4 = generate_otp(test_user)
    print(f"Generated OTP for {test_user}: {otp4} (for testing)")
    print(f"Waiting for {OTP_VALIDITY_SECONDS + 1} seconds to simulate expiration...")
    time.sleep(OTP_VALIDITY_SECONDS + 1)
    is_valid4 = verify_otp(test_user, otp4)
    print(f"Verification of expired OTP successful: {is_valid4}\n")

    # Test Case 5: Verification for a user with no generated OTP
    print("--- Test Case 5: No OTP Generated for User ---")
    is_valid5 = verify_otp("nouser@example.com", "123456")
    print(f"Verification for non-existent OTP successful: {is_valid5}\n")

if __name__ == "__main__":
    main()