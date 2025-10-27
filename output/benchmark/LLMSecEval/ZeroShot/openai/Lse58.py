import os
import hmac
import hashlib

class User:
    def __init__(self, email: str, salt: bytes, password_hash: bytes):
        self.email = email
        self.salt = salt
        self.password_hash = password_hash
        self.logged_in = False

def _pbkdf2(password: str, salt: bytes, iterations: int = 120000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

def register_user(email: str, password: str) -> User:
    if email is None or password is None:
        raise ValueError("email/password cannot be None")
    salt = os.urandom(16)
    ph = _pbkdf2(password, salt)
    return User(email, salt, ph)

def login(user: User, email: str, password: str) -> bool:
    if user is None or email is None or password is None:
        return False
    if email != user.email:
        return False
    ph = _pbkdf2(password, user.salt)
    ok = hmac.compare_digest(ph, user.password_hash)
    if ok:
        user.logged_in = True
    return ok

def logout(user: User) -> None:
    if user:
        user.logged_in = False

def change_email(user: User, old_email: str, password: str, new_email: str) -> bool:
    if user is None or old_email is None or password is None or new_email is None:
        return False
    if not user.logged_in:
        return False
    if user.email != old_email:
        return False
    ph = _pbkdf2(password, user.salt)
    if not hmac.compare_digest(ph, user.password_hash):
        return False
    user.email = new_email
    return True

if __name__ == "__main__":
    # Test Case 1: Successful login and email change
    u1 = register_user("user@example.com", "StrongPass!123")
    t1_login = login(u1, "user@example.com", "StrongPass!123")
    t1_change = change_email(u1, "user@example.com", "StrongPass!123", "new1@example.com")
    print(f"TC1 login: {t1_login}, change: {t1_change}, email: {u1.email}")

    # Test Case 2: Attempt change without login
    u2 = register_user("alpha@ex.com", "Ap@55word")
    t2_change = change_email(u2, "alpha@ex.com", "Ap@55word", "alpha2@ex.com")
    print(f"TC2 change without login: {t2_change}, email: {u2.email}")

    # Test Case 3: Wrong old email after login
    u3 = register_user("beta@ex.com", "BetaSecure1!")
    t3_login = login(u3, "beta@ex.com", "BetaSecure1!")
    t3_change = change_email(u3, "wrong@ex.com", "BetaSecure1!", "beta2@ex.com")
    print(f"TC3 login: {t3_login}, change with wrong old email: {t3_change}, email: {u3.email}")

    # Test Case 4: Wrong password after login
    u4 = register_user("gamma@ex.com", "GammaStrong1#")
    t4_login = login(u4, "gamma@ex.com", "GammaStrong1#")
    t4_change = change_email(u4, "gamma@ex.com", "WrongPass", "gamma2@ex.com")
    print(f"TC4 login: {t4_login}, change with wrong password: {t4_change}, email: {u4.email}")

    # Test Case 5: Change email again after re-login with updated email
    logout(u1)
    t5_login = login(u1, "new1@example.com", "StrongPass!123")
    t5_change = change_email(u1, "new1@example.com", "StrongPass!123", "final@example.com")
    print(f"TC5 login with updated email: {t5_login}, change: {t5_change}, email: {u1.email}")