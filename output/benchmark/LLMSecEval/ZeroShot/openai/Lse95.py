import os
import hmac
import hashlib
import secrets
import re

class Lse95:
    _DB = {}
    _USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,32}$')
    _ITERATIONS = 100_000
    _DKLEN = 32
    _SALT_LEN = 16

    @staticmethod
    def register_user(username: str, password: str) -> bool:
        if not Lse95._valid_username(username) or not Lse95._valid_password(password):
            return False
        if username in Lse95._DB:
            return False
        salt = secrets.token_bytes(Lse95._SALT_LEN)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, Lse95._ITERATIONS, Lse95._DKLEN)
        stored = dk.hex() + ":" + salt.hex()
        Lse95._DB[username] = stored
        return True

    @staticmethod
    def login_user(username: str, password: str) -> bool:
        stored = Lse95._DB.get(username)
        if not stored:
            return False
        try:
            hex_hash, hex_salt = stored.split(":")
        except ValueError:
            return False
        salt = bytes.fromhex(hex_salt)
        expected = bytes.fromhex(hex_hash)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, Lse95._ITERATIONS, Lse95._DKLEN)
        return hmac.compare_digest(expected, dk)

    @staticmethod
    def _valid_username(username: str) -> bool:
        return isinstance(username, str) and Lse95._USERNAME_RE.fullmatch(username) is not None

    @staticmethod
    def _valid_password(password: str) -> bool:
        return isinstance(password, str) and len(password) >= 8

if __name__ == "__main__":
    print("Register alice:", Lse95.register_user("alice", "Str0ngP@ss!"))
    print("Login alice (correct):", Lse95.login_user("alice", "Str0ngP@ss!"))
    print("Register bob:", Lse95.register_user("bob", "anotherS3cure"))
    print("Login bob (wrong):", Lse95.login_user("bob", "wrongpass"))
    print("Register alice again (duplicate):", Lse95.register_user("alice", "NewPassw0rd!"))
    print("Register charlie_01 (too short):", Lse95.register_user("charlie_01", "short"))
    print("Register dave:", Lse95.register_user("dave", "CorrectHorseBatteryStaple1!"))
    print("Login dave (correct):", Lse95.login_user("dave", "CorrectHorseBatteryStaple1!"))
    print("Login unknown user:", Lse95.login_user("eve", "SomePass123"))