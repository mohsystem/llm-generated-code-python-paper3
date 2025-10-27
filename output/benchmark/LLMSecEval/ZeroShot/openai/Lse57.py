import os
import re
import hmac
import secrets
import hashlib

class AuthSystem:
    def __init__(self):
        self.users = {}  # email_lower -> {email, salt, hash}
        self.sessions = {}  # token -> email_lower
        self.email_re = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
        self.iterations = 100_000
        self.salt_len = 16
        self.key_len = 32

    def _valid_email(self, email: str) -> bool:
        if not email or len(email) > 254:
            return False
        return bool(self.email_re.match(email))

    def _hash_password(self, password: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password, salt, self.iterations, dklen=self.key_len)

    def register_user(self, email: str, password: str) -> bool:
        if not self._valid_email(email) or not password:
            return False
        email_l = email.lower()
        if email_l in self.users:
            return False
        salt = os.urandom(self.salt_len)
        pw_hash = self._hash_password(password.encode('utf-8'), salt)
        self.users[email_l] = {'email': email, 'salt': salt, 'hash': pw_hash}
        return True

    def login(self, email: str, password: str) -> str:
        email_l = (email or "").lower()
        user = self.users.get(email_l)
        if not user:
            return ""
        pw_hash = self._hash_password(password.encode('utf-8'), user['salt'])
        if not hmac.compare_digest(pw_hash, user['hash']):
            return ""
        token = secrets.token_urlsafe(24)
        self.sessions[token] = email_l
        return token

    def change_email(self, session_token: str, old_email: str, new_email: str, confirm_password: str) -> bool:
        if not session_token or not old_email or not new_email or confirm_password is None:
            return False
        if not self._valid_email(new_email):
            return False
        email_l = self.sessions.get(session_token)
        if not email_l:
            return False
        if email_l != old_email.lower():
            return False
        user = self.users.get(email_l)
        if not user:
            return False
        if new_email.lower() in self.users:
            return False
        pw_hash = self._hash_password(confirm_password.encode('utf-8'), user['salt'])
        if not hmac.compare_digest(pw_hash, user['hash']):
            return False
        # Update
        del self.users[email_l]
        new_email_l = new_email.lower()
        self.users[new_email_l] = {'email': new_email, 'salt': user['salt'], 'hash': user['hash']}
        self.sessions[session_token] = new_email_l
        return True

def main():
    auth = AuthSystem()
    print("Register Alice:", auth.register_user("alice@example.com", "CorrectHorseBatteryStaple!"))
    print("Register Bob:", auth.register_user("bob@example.com", "B0bStrong#Pass"))
    token = auth.login("alice@example.com", "CorrectHorseBatteryStaple!")
    print("Alice token present:", bool(token))

    # Test 1: invalid session
    print("Test1 (invalid session):", auth.change_email("badtoken", "alice@example.com", "alice_new@example.com", "CorrectHorseBatteryStaple!"))
    # Test 2: wrong old email
    print("Test2 (wrong old email):", auth.change_email(token, "wrong@example.com", "alice_new@example.com", "CorrectHorseBatteryStaple!"))
    # Test 3: wrong password
    print("Test3 (wrong password):", auth.change_email(token, "alice@example.com", "alice_new@example.com", "wrongpass"))
    # Test 4: new email already exists
    print("Test4 (email exists):", auth.change_email(token, "alice@example.com", "bob@example.com", "CorrectHorseBatteryStaple!"))
    # Test 5: success
    print("Test5 (success):", auth.change_email(token, "alice@example.com", "alice2@example.com", "CorrectHorseBatteryStaple!"))
    # Verify login with new email
    print("Login with new email works:", bool(auth.login("alice2@example.com", "CorrectHorseBatteryStaple!")))

if __name__ == "__main__":
    main()