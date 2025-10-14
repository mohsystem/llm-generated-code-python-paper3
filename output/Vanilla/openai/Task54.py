import random
import time

class OTPManager:
    def __init__(self):
        self.store = {}  # username -> (code, expiry_epoch_seconds)
        self.rng = random.SystemRandom()

    def generate_otp(self, username: str, length: int = 6, ttl_seconds: int = 120) -> str:
        code = ''.join(str(self.rng.randrange(10)) for _ in range(length))
        expiry = time.time() + ttl_seconds
        self.store[username] = (code, expiry)
        return code

    def verify_otp(self, username: str, code: str) -> bool:
        entry = self.store.get(username)
        if not entry:
            return False
        saved_code, expiry = entry
        now = time.time()
        if now > expiry:
            self.store.pop(username, None)
            return False
        if saved_code == code:
            self.store.pop(username, None)  # one-time use
            return True
        return False

class AuthService:
    def __init__(self, otp_manager: OTPManager):
        self.users = {}
        self.otp_manager = otp_manager

    def add_user(self, username: str, password: str):
        self.users[username] = password

    def start_login(self, username: str, password: str, otp_length: int = 6, ttl_seconds: int = 120):
        if username in self.users and self.users[username] == password:
            return self.otp_manager.generate_otp(username, otp_length, ttl_seconds)
        return None

    def finish_login(self, username: str, otp: str) -> bool:
        if otp is None:
            return False
        return self.otp_manager.verify_otp(username, otp)

def main():
    otp_mgr = OTPManager()
    auth = AuthService(otp_mgr)
    auth.add_user("alice", "password123")
    auth.add_user("bob", "qwerty")
    auth.add_user("charlie", "letmein")
    auth.add_user("dave", "passw0rd")
    auth.add_user("eve", "123456")

    # Test 1: Successful login
    otp1 = auth.start_login("alice", "password123", 6, 120)
    t1 = auth.finish_login("alice", otp1)
    print(f"Test1:{t1}")

    # Test 2: Wrong password
    otp2 = auth.start_login("bob", "wrong", 6, 120)
    t2 = auth.finish_login("bob", "000000")
    print(f"Test2:{t2}")

    # Test 3: Correct password, wrong OTP
    otp3 = auth.start_login("charlie", "letmein", 6, 120)
    t3 = auth.finish_login("charlie", "111111")
    print(f"Test3:{t3}")

    # Test 4: Expired OTP
    otp4 = auth.start_login("dave", "passw0rd", 6, 1)
    time.sleep(1.5)
    t4 = auth.finish_login("dave", otp4)
    print(f"Test4:{t4}")

    # Test 5: Reuse OTP attempt
    otp5 = auth.start_login("eve", "123456", 6, 120)
    t5a = auth.finish_login("eve", otp5)
    t5b = auth.finish_login("eve", otp5)
    print(f"Test5:{t5a and not t5b}")

if __name__ == "__main__":
    main()