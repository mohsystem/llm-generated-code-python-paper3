
import hmac
import hashlib
import secrets
import time
import base64
from typing import Dict, Optional, Tuple

class Task54:
    OTP_LENGTH: int = 6
    TIME_STEP: int = 30
    SECRET_KEY_LENGTH: int = 32
    SALT_LENGTH: int = 16
    PBKDF2_ITERATIONS: int = 210000
    
    def __init__(self) -> None:
        self.user_database: Dict[str, Tuple[bytes, bytes, bytes]] = {}
    
    def register_user(self, username: str, password: str) -> str:
        if not username or not isinstance(username, str) or len(username.strip()) == 0 or len(username) > 100:
            return "ERROR: Invalid username"
        if not password or not isinstance(password, str) or len(password) < 8 or len(password) > 128:
            return "ERROR: Password must be 8-128 characters"
        if not self._is_strong_password(password):
            return "ERROR: Password must contain uppercase, lowercase, digit, and special character"
        if username in self.user_database:
            return "ERROR: User already exists"
        
        try:
            salt = secrets.token_bytes(self.SALT_LENGTH)
            password_hash = self._hash_password(password, salt)
            totp_secret = secrets.token_bytes(self.SECRET_KEY_LENGTH)
            
            self.user_database[username] = (password_hash, salt, totp_secret)
            
            secret_base64 = base64.b64encode(totp_secret).decode('utf-8')
            return f"SUCCESS: User registered. TOTP Secret: {secret_base64}"
        except Exception:
            return "ERROR: Registration failed"
    
    def login(self, username: str, password: str, otp: str) -> str:
        if not username or not isinstance(username, str) or len(username.strip()) == 0:
            return "ERROR: Invalid username"
        if not password or not isinstance(password, str):
            return "ERROR: Invalid password"
        if not otp or not isinstance(otp, str) or not otp.isdigit() or len(otp) != 6:
            return "ERROR: Invalid OTP format"
        
        user_data = self.user_database.get(username)
        if user_data is None:
            self._perform_dummy_work()
            return "ERROR: Authentication failed"
        
        try:
            password_hash, salt, totp_secret = user_data
            computed_hash = self._hash_password(password, salt)
            
            if not self._constant_time_equals(computed_hash, password_hash):
                return "ERROR: Authentication failed"
            
            if not self._verify_totp(totp_secret, otp):
                return "ERROR: Invalid OTP"
            
            return "SUCCESS: Login successful"
        except Exception:
            return "ERROR: Authentication failed"
    
    def generate_otp(self, username: str) -> str:
        if not username or not isinstance(username, str) or len(username.strip()) == 0:
            return "ERROR: Invalid username"
        
        user_data = self.user_database.get(username)
        if user_data is None:
            return "ERROR: User not found"
        
        try:
            _, _, totp_secret = user_data
            time_counter = int(time.time()) // self.TIME_STEP
            otp = self._generate_totp(totp_secret, time_counter)
            return otp
        except Exception:
            return "ERROR: OTP generation failed"
    
    def _is_strong_password(self, password: str) -> bool:
        if not password or len(password) < 8:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        return has_upper and has_lower and has_digit and has_special
    
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.PBKDF2_ITERATIONS,
            dklen=32
        )
    
    def _generate_totp(self, secret: bytes, counter: int) -> str:
        time_bytes = counter.to_bytes(8, byteorder='big')
        
        mac = hmac.new(secret, time_bytes, hashlib.sha256)
        hash_value = mac.digest()
        
        offset = hash_value[-1] & 0x0F
        binary = ((hash_value[offset] & 0x7F) << 24 |
                  (hash_value[offset + 1] & 0xFF) << 16 |
                  (hash_value[offset + 2] & 0xFF) << 8 |
                  (hash_value[offset + 3] & 0xFF))
        
        otp = binary % 1000000
        return f"{otp:06d}"
    
    def _verify_totp(self, secret: bytes, otp: str) -> bool:
        try:
            current_time = int(time.time()) // self.TIME_STEP
            
            for i in range(-1, 2):
                generated_otp = self._generate_totp(secret, current_time + i)
                if self._constant_time_equals(otp.encode('utf-8'), generated_otp.encode('utf-8')):
                    return True
            return False
        except Exception:
            return False
    
    def _constant_time_equals(self, a: bytes, b: bytes) -> bool:
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            return False
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    def _perform_dummy_work(self) -> None:
        try:
            dummy_salt = secrets.token_bytes(self.SALT_LENGTH)
            self._hash_password("dummy", dummy_salt)
        except Exception:
            pass


def main() -> None:
    auth = Task54()
    
    print("Test Case 1: Register new user")
    result1 = auth.register_user("alice", "SecureP@ss123")
    print(result1)
    
    print("\\nTest Case 2: Generate OTP for alice")
    otp = auth.generate_otp("alice")
    print(f"Generated OTP: {otp}")
    
    print("\\nTest Case 3: Login with correct credentials and OTP")
    result3 = auth.login("alice", "SecureP@ss123", otp)
    print(result3)
    
    print("\\nTest Case 4: Login with incorrect OTP")
    result4 = auth.login("alice", "SecureP@ss123", "000000")
    print(result4)
    
    print("\\nTest Case 5: Login with incorrect password")
    result5 = auth.login("alice", "WrongPassword", otp)
    print(result5)


if __name__ == "__main__":
    main()
