
import hashlib
import uuid
import time
from typing import Dict, Optional

class Lse55:
    users = {}
    sessions = {}
    
    class User:
        def __init__(self, username: str, password_hash: str, role: str):
            self.username = username
            self.password_hash = password_hash
            self.role = role
    
    class Session:
        def __init__(self, username: str, role: str):
            self.username = username
            self.role = role
            self.expiry_time = time.time() + 3600  # 1 hour
        
        def is_valid(self) -> bool:
            return time.time() < self.expiry_time
    
    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def generate_session_token() -> str:
        return str(uuid.uuid4())
    
    @staticmethod
    def login() -> str:
        return "LOGIN_PAGE: Please provide username and password"
    
    @staticmethod
    def do_login(username: Optional[str], password: Optional[str]) -> Dict[str, str]:
        response = {}
        
        if not username or not password or not username.strip():
            response["status"] = "error"
            response["message"] = "Invalid credentials"
            return response
        
        username = username.strip()
        user = Lse55.users.get(username)
        
        if not user or user.password_hash != Lse55.hash_password(password):
            response["status"] = "error"
            response["message"] = "Invalid credentials"
            return response
        
        session_token = Lse55.generate_session_token()
        Lse55.sessions[session_token] = Lse55.Session(user.username, user.role)
        
        response["status"] = "success"
        response["sessionToken"] = session_token
        response["message"] = "Login successful"
        return response
    
    @staticmethod
    def index() -> str:
        return "INDEX_PAGE: Welcome to the home page"
    
    @staticmethod
    def user_page(session_token: Optional[str]) -> str:
        if not session_token:
            return "ERROR: Authentication required"
        
        session = Lse55.sessions.get(session_token)
        if not session or not session.is_valid():
            return "ERROR: Invalid or expired session"
        
        return f"USER_PAGE: Welcome {session.username}!"
    
    @staticmethod
    def admin_page(session_token: Optional[str]) -> str:
        if not session_token:
            return "ERROR: Authentication required"
        
        session = Lse55.sessions.get(session_token)
        if not session or not session.is_valid():
            return "ERROR: Invalid or expired session"
        
        if session.role != "admin":
            return "ERROR: Unauthorized - Admin access required"
        
        return f"ADMIN_PAGE: Welcome Admin {session.username}!"


if __name__ == "__main__":
    # Initialize test users
    Lse55.users["user1"] = Lse55.User("user1", Lse55.hash_password("password123"), "user")
    Lse55.users["admin1"] = Lse55.User("admin1", Lse55.hash_password("admin123"), "admin")
    
    print("=== Test Case 1: Login page ===")
    print(Lse55.login())
    print()
    
    print("=== Test Case 2: Failed login ===")
    result1 = Lse55.do_login("user1", "wrongpassword")
    print(result1)
    print()
    
    print("=== Test Case 3: Successful user login ===")
    result2 = Lse55.do_login("user1", "password123")
    print(result2)
    user_token = result2.get("sessionToken")
    print()
    
    print("=== Test Case 4: User accessing user page ===")
    print(Lse55.user_page(user_token))
    print()
    
    print("=== Test Case 5: User accessing admin page (should fail) ===")
    print(Lse55.admin_page(user_token))
    print()
    
    print("=== Test Case 6: Admin login and access ===")
    result3 = Lse55.do_login("admin1", "admin123")
    admin_token = result3.get("sessionToken")
    print(Lse55.admin_page(admin_token))
    print()
    
    print("=== Test Case 7: Index page ===")
    print(Lse55.index())
