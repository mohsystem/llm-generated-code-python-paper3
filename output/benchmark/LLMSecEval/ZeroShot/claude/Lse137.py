
import hashlib
import base64
import time
from typing import Dict, Optional

class User:
    def __init__(self, username: str, password_hash: str, is_moderator: bool):
        self.username = username
        self.password_hash = password_hash
        self.is_moderator = is_moderator

class Session:
    def __init__(self, session_id: str, username: str, expiry_time: int):
        self.session_id = session_id
        self.username = username
        self.expiry_time = expiry_time
    
    def is_valid(self) -> bool:
        return time.time() < self.expiry_time

users: Dict[str, User] = {}
sessions: Dict[str, Session] = {}

def hash_password(password: str) -> str:
    return base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()

def auth_mod(username: str, password: str, session_id: str) -> bool:
    if not username or not password or not session_id:
        return False
    
    session = sessions.get(session_id)
    if not session or not session.is_valid() or session.username != username:
        return False
    
    user = users.get(username)
    if not user:
        return False
    
    hashed_password = hash_password(password)
    if user.password_hash != hashed_password:
        return False
    
    return user.is_moderator

def check_mod(username: str, password: str, session_id: str) -> bool:
    return auth_mod(username, password, session_id)

if __name__ == "__main__":
    # Setup test data
    users["admin"] = User("admin", hash_password("admin123"), True)
    users["user1"] = User("user1", hash_password("pass123"), False)
    users["mod1"] = User("mod1", hash_password("modpass"), True)
    
    valid_session = "session123"
    sessions[valid_session] = Session(valid_session, "admin", time.time() + 3600)
    
    valid_session2 = "session456"
    sessions[valid_session2] = Session(valid_session2, "user1", time.time() + 3600)
    
    valid_session3 = "session789"
    sessions[valid_session3] = Session(valid_session3, "mod1", time.time() + 3600)
    
    # Test cases
    print(f"Test 1 (Valid moderator): {check_mod('admin', 'admin123', valid_session)}")
    print(f"Test 2 (Valid non-moderator): {check_mod('user1', 'pass123', valid_session2)}")
    print(f"Test 3 (Invalid password): {check_mod('admin', 'wrongpass', valid_session)}")
    print(f"Test 4 (Invalid session): {check_mod('admin', 'admin123', 'invalidsession')}")
    print(f"Test 5 (Another valid moderator): {check_mod('mod1', 'modpass', valid_session3)}")
