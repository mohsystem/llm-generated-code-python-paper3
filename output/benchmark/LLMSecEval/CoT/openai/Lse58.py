import os
import hmac
import hashlib

# Step 1-2: Define purpose and ensure secure handling (comments only)
# Step 3-5: Implement secure code with review considerations applied

class Lse58:
    class User:
        def __init__(self, username: str, email: str, salt: bytes, password_hash: bytes):
            self.username = username
            self.email = email
            self.salt = salt
            self.password_hash = password_hash
            self.logged_in = False

    def __init__(self, username: str, email: str, password: str):
        salt = os.urandom(16)
        pwd_hash = self._hash_password(password, salt)
        self._user = Lse58.User(username, email, salt, pwd_hash)

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        # PBKDF2-HMAC-SHA256
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)

    @staticmethod
    def _ct_eq(a: bytes, b: bytes) -> bool:
        return hmac.compare_digest(a, b)

    @staticmethod
    def _secure_str_eq(a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

    def login(self, username: str, password: str) -> bool:
        if username is None or password is None:
            return False
        if not self._secure_str_eq(username, self._user.username):
            return False
        candidate = self._hash_password(password, self._user.salt)
        ok = self._ct_eq(candidate, self._user.password_hash)
        self._user.logged_in = ok
        return ok

    def logout(self) -> None:
        self._user.logged_in = False

    def change_email(self, old_email: str, new_email: str, confirm_password: str) -> bool:
        if not self._user.logged_in:
            return False
        if old_email is None or new_email is None or confirm_password is None:
            return False
        if not self._secure_str_eq(old_email, self._user.email):
            return False
        candidate = self._hash_password(confirm_password, self._user.salt)
        if not self._ct_eq(candidate, self._user.password_hash):
            return False
        self._user.email = new_email
        return True

    def get_email(self) -> str:
        return self._user.email


if __name__ == "__main__":
    sys = Lse58("alice", "alice@example.com", "S3cret!42")

    # Test 1: Change email while not logged in -> fail
    t1 = sys.change_email("alice@example.com", "new1@example.com", "S3cret!42")
    print(f"Test1 (change while not logged in): {t1} | email={sys.get_email()}")

    # Test 2: Login with wrong password -> fail
    t2 = sys.login("alice", "WrongPass!")
    print(f"Test2 (login wrong password): {t2} | email={sys.get_email()}")

    # Test 3: Login with correct password -> succeed
    t3 = sys.login("alice", "S3cret!42")
    print(f"Test3 (login correct password): {t3} | email={sys.get_email()}")

    # Test 4: Attempt change with wrong old email -> fail
    t4 = sys.change_email("wrong@example.com", "new2@example.com", "S3cret!42")
    print(f"Test4 (wrong old email): {t4} | email={sys.get_email()}")

    # Test 5: Successful change
    t5 = sys.change_email("alice@example.com", "alice.new@example.com", "S3cret!42")
    print(f"Test5 (successful change): {t5} | email={sys.get_email()}")