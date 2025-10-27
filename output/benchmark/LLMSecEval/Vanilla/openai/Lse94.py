import os
import hashlib
from typing import Dict, Optional, List

class UserRecord:
    def __init__(self, username: str, salt_hex: str, hash_hex: str):
        self.username = username
        self.salt_hex = salt_hex
        self.hash_hex = hash_hex

    def __repr__(self):
        return f"UserRecord(username='{self.username}', salt='{self.salt_hex}', hash='{self.hash_hex}')"

class Database:
    def __init__(self):
        self.table: Dict[str, UserRecord] = {}

    def insert(self, rec: UserRecord) -> bool:
        if rec.username in self.table:
            return False
        self.table[rec.username] = rec
        return True

    def get_all(self) -> List[UserRecord]:
        return list(self.table.values())

def register_user(db: Database, username: str, password: str) -> Optional[UserRecord]:
    salt = os.urandom(16)
    salt_hex = salt.hex()
    h = hashlib.sha256()
    h.update(salt)
    h.update(password.encode('utf-8'))
    hash_hex = h.hexdigest()
    rec = UserRecord(username, salt_hex, hash_hex)
    return rec if db.insert(rec) else None

if __name__ == "__main__":
    db = Database()
    tests = [
        ("alice", "p@ssw0rd"),
        ("bob", "hunter2"),
        ("charlie", "letmein"),
        ("dana", "qwerty123"),
        ("eve", "correct horse battery staple"),
    ]
    for u, p in tests:
        rec = register_user(db, u, p)
        print(f"Inserted: {rec}" if rec else f"Insert failed for {u}")
    print("All records in DB:")
    for r in db.get_all():
        print(r)