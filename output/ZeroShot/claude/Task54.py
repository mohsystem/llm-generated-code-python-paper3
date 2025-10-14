
import secrets
import time
from typing import Dict, Optional, Tuple

class Task54:
    def __init__(self):
        self.user_database: Dict[str, str] = {}
        self.otp_storage: Dict[str, str] = {}
        self.otp_expiry: Dict[str, float] = {}
        self.OTP_LENGTH = 6
        self.OTP_VALIDITY = 300  # 5 minutes in seconds

    def generate_otp(self) -> str:
        """Generate a secure random OTP"""
        otp = ''.join([str(secrets.randbelow(10)) for _ in range(self.OTP_LENGTH)])
        return otp

    def register_user(self, username: str, password: str) -> bool:
        """Register a new user"""
        if not username or not password:
            return False
        if username in self.user_database:
            return False
        self.user_database[username] = password
        return True

    def authenticate_and_generate_otp(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and generate OTP"""
        if not username or not password:
            return None
        if username not in self.user_database:
            return None
        if self.user_database[username] != password:
            return None
        
        otp = self.generate_otp()
        self.otp_storage[username] = otp
        self.otp_expiry[username] = time.time() + self.OTP_VALIDITY
        return otp

    def verify_otp(self, username: str, otp: str) -> bool:
        """Verify the OTP"""
        if not username or not otp:
            return False
        if username not in self.otp_storage:
            return False
        
        if time.time() > self.otp_expiry[username]:
            del self.otp_storage[username]
            del self.otp_expiry[username]
            return False
        
        is_valid = self.otp_storage[username] == otp
        if is_valid:
            del self.otp_storage[username]
            del self.otp_expiry[username]
        return is_valid


def main():
    print("=== Two-Factor Authentication Test Cases ===\\n")
    
    # Test Case 1: Register and successful 2FA
    print("Test Case 1: Successful Registration and 2FA")
    auth_system = Task54()
    auth_system.register_user("user1", "password123")
    otp1 = auth_system.authenticate_and_generate_otp("user1", "password123")
    print(f"Generated OTP: {otp1}")
    result1 = auth_system.verify_otp("user1", otp1)
    print(f"2FA Result: {'SUCCESS' if result1 else 'FAILED'}")
    print()

    # Test Case 2: Invalid password
    print("Test Case 2: Invalid Password")
    auth_system2 = Task54()
    auth_system2.register_user("user2", "securepass")
    otp2 = auth_system2.authenticate_and_generate_otp("user2", "wrongpass")
    print(f"OTP Generation: {'FAILED (Invalid credentials)' if otp2 is None else 'SUCCESS'}")
    print()

    # Test Case 3: Wrong OTP
    print("Test Case 3: Wrong OTP")
    auth_system3 = Task54()
    auth_system3.register_user("user3", "mypassword")
    otp3 = auth_system3.authenticate_and_generate_otp("user3", "mypassword")
    print(f"Generated OTP: {otp3}")
    result3 = auth_system3.verify_otp("user3", "000000")
    print(f"2FA with wrong OTP: {'SUCCESS' if result3 else 'FAILED'}")
    print()

    # Test Case 4: Reusing OTP
    print("Test Case 4: Reusing OTP")
    auth_system4 = Task54()
    auth_system4.register_user("user4", "pass456")
    otp4 = auth_system4.authenticate_and_generate_otp("user4", "pass456")
    print(f"Generated OTP: {otp4}")
    result4a = auth_system4.verify_otp("user4", otp4)
    print(f"First verification: {'SUCCESS' if result4a else 'FAILED'}")
    result4b = auth_system4.verify_otp("user4", otp4)
    print(f"Second verification (reuse): {'SUCCESS' if result4b else 'FAILED'}")
    print()

    # Test Case 5: Non-existent user
    print("Test Case 5: Non-existent User")
    auth_system5 = Task54()
    otp5 = auth_system5.authenticate_and_generate_otp("nonexistent", "password")
    print(f"OTP Generation for non-existent user: {'FAILED (User not found)' if otp5 is None else 'SUCCESS'}")
    print()


if __name__ == "__main__":
    main()
