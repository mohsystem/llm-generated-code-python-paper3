import hashlib
from dataclasses import dataclass

@dataclass
class User:
    username: str
    password_hash: str

class Lse92:
    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    @staticmethod
    def register_user(username: str, password: str) -> User:
        return User(username=username, password_hash=Lse92.hash_password(password))

if __name__ == "__main__":
    tests = [
        ("alice", "p@ssw0rd"),
        ("bob", "letmein"),
        ("charlie", "123456"),
        ("diana", "correcthorsebatterystaple"),
        ("eve", "Tr0ub4dor&3"),
    ]
    for u, p in tests:
        user = Lse92.register_user(u, p)
        print(user)