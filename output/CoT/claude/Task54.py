
import hashlib
import secrets
import time
from typing import Dict, Optional

class Task54:
    OTP_LENGTH = 6
    OTP_VALIDITY_SECONDS = 300  # 5 minutes
    
    def __init__(self):
        self.otp_storage: Dict[str, dict] = {}
        self.user_credentials: Dict[str, str] = {}
    
    def generate_otp(self) -> str:
        """Generate a secure random OTP"""
        otp = ''.join([str(secrets.randbelow(10)) for _ in range(self.OTP_LENGTH)])
        return otp
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username: str, password: str) -> None:
        """Register a new user with hashed password"""
        if not username or not username.strip():
            raise ValueError("Invalid username")
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        hashed_password = self.hash_password(password)
        self.user_credentials[username] = hashed_password
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user with username and password"""
        if not username or not password:
            return False
        
        stored_hash = self.user_credentials.get(username)
        if not stored_hash:
            return False
        
        input_hash = self.hash_password(password)
        return stored_hash == input_hash
    
    def send_otp(self, username: str) -> str:
        """Generate and store OTP for user"""
        if username not in self.user_credentials:
            raise ValueError("User not found")
        
        otp = self.generate_otp()
        hashed_otp = self.hash_password(otp)
        expiry_time = time.time() + self.OTP_VALIDITY_SECONDS
        
        self.otp_storage[username] = {
            'hashed_otp': hashed_otp,
            'expiry_time': expiry_time,
            'attempts': 0
        }
        
        return otp
    
    def verify_otp(self, username: str, otp: str) -> bool:
        """Verify the OTP for a user"""
        if not username or not otp:
            return False
        
        otp_data = self.otp_storage.get(username)
        if not otp_data:
            return False
        
        # Check attempt limit
        if otp_data['attempts'] >= 3:
            del self.otp_storage[username]
            return False
        
        otp_data['attempts'] += 1
        
        # Check expiry
        current_time = time.time()
        if current_time > otp_data['expiry_time']:
            del self.otp_storage[username]
            return False
        
        # Verify OTP
        hashed_input_otp = self.hash_password(otp)
        is_valid = otp_data['hashed_otp'] == hashed_input_otp
        
        if is_valid:
            del self.otp_storage[username]
        
        return is_valid
    
    def two_factor_login(self, username: str, password: str, otp: str) -> bool:
        """Perform two-factor authentication"""
        if not self.authenticate_user(username, password):
            return False
        return self.verify_otp(username, otp)


def main():
    print("Two-Factor Authentication System Test Cases\\n")
    
    # Test Case 1: Successful 2FA login
    print("Test Case 1: Successful 2FA login")
    auth1 = Task54()
    auth1.register_user("user1", "SecurePass123")
    otp1 = auth1.send_otp("user1")
    result1 = auth1.two_factor_login("user1", "SecurePass123", otp1)
    print(f"Result: {'SUCCESS' if result1 else 'FAILED'}\\n")
    
    # Test Case 2: Wrong password
    print("Test Case 2: Wrong password")
    auth2 = Task54()
    auth2.register_user("user2", "SecurePass456")
    otp2 = auth2.send_otp("user2")
    result2 = auth2.two_factor_login("user2", "WrongPassword", otp2)
    print(f"Result: {'SUCCESS' if result2 else 'FAILED (Expected)'}\\n")
    
    # Test Case 3: Wrong OTP
    print("Test Case 3: Wrong OTP")
    auth3 = Task54()
    auth3.register_user("user3", "SecurePass789")
    auth3.send_otp("user3")
    result3 = auth3.two_factor_login("user3", "SecurePass789", "000000")
    print(f"Result: {'SUCCESS' if result3 else 'FAILED (Expected)'}\\n")
    
    # Test Case 4: Valid OTP verification
    print("Test Case 4: Valid OTP verification")
    auth4 = Task54()
    auth4.register_user("user4", "SecurePass101")
    otp4 = auth4.send_otp("user4")
    result4 = auth4.verify_otp("user4", otp4)
    print(f"Result: {'SUCCESS' if result4 else 'FAILED'}\\n")
    
    # Test Case 5: Multiple users
    print("Test Case 5: Multiple users handling")
    auth5 = Task54()
    auth5.register_user("user5", "SecurePass202")
    auth5.register_user("user6", "SecurePass303")
    otp5 = auth5.send_otp("user5")
    otp6 = auth5.send_otp("user6")
    result5a = auth5.two_factor_login("user5", "SecurePass202", otp5)
    result5b = auth5.two_factor_login("user6", "SecurePass303", otp6)
    print(f"User5 Result: {'SUCCESS' if result5a else 'FAILED'}")
    print(f"User6 Result: {'SUCCESS' if result5b else 'FAILED'}")


if __name__ == "__main__":
    main()
