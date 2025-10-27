
import hashlib
import uuid
from typing import Dict, Optional

class User:
    def __init__(self, username: str, password_hash: str, role: str):
        self.username = username
        self.password_hash = password_hash
        self.role = role

class Lse55:
    # In-memory storage
    users: Dict[str, User] = {}
    sessions: Dict[str, str] = {}
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def initialize_users():
        """Initialize test users"""
        Lse55.users = {
            "admin": User("admin", Lse55.hash_password("admin123"), "admin"),
            "user1": User("user1", Lse55.hash_password("user123"), "user"),
            "user2": User("user2", Lse55.hash_password("pass123"), "user"),
            "testuser": User("testuser", Lse55.hash_password("test123"), "user"),
            "john": User("john", Lse55.hash_password("john123"), "user")
        }
    
    @staticmethod
    def login() -> str:
        """GET /login - Display login page"""
        return "LOGIN_PAGE: Please enter username and password"
    
    @staticmethod
    def do_login(username: str, password: str) -> str:
        """POST /login - Process login"""
        if not username or not password:
            return "ERROR: Username and password required"
        
        user = Lse55.users.get(username)
        if not user:
            return "ERROR: Invalid credentials"
        
        hashed_password = Lse55.hash_password(password)
        if user.password_hash != hashed_password:
            return "ERROR: Invalid credentials"
        
        # Create session
        session_id = str(uuid.uuid4())
        Lse55.sessions[session_id] = username
        
        return f"SUCCESS: Logged in as {username} | Session: {session_id}"
    
    @staticmethod
    def index(session_id: Optional[str] = None) -> str:
        """GET /index - Home page"""
        if not session_id or session_id not in Lse55.sessions:
            return "INDEX_PAGE: Welcome! Please login to continue."
        
        username = Lse55.sessions[session_id]
        return f"INDEX_PAGE: Welcome {username}! You are logged in."
    
    @staticmethod
    def user_page(session_id: Optional[str] = None) -> str:
        """GET /user - User page"""
        if not session_id or session_id not in Lse55.sessions:
            return "ERROR: Unauthorized. Please login first."
        
        username = Lse55.sessions[session_id]
        user = Lse55.users.get(username)
        
        if not user:
            return "ERROR: User not found"
        
        return f"USER_PAGE: Hello {username}! This is your user dashboard."
    
    @staticmethod
    def admin_page(session_id: Optional[str] = None) -> str:
        """GET /admin - Admin page"""
        if not session_id or session_id not in Lse55.sessions:
            return "ERROR: Unauthorized. Please login first."
        
        username = Lse55.sessions[session_id]
        user = Lse55.users.get(username)
        
        if not user or user.role != "admin":
            return "ERROR: Forbidden. Admin access required."
        
        return f"ADMIN_PAGE: Welcome Admin {username}! You have full access."


def main():
    # Initialize users
    Lse55.initialize_users()
    
    print("=== Test Case 1: Access login page ===")
    print(Lse55.login())
    
    print("\\n=== Test Case 2: Successful user login ===")
    session1 = Lse55.do_login("user1", "user123")
    print(session1)
    session_id1 = session1.split("Session: ")[1] if "Session:" in session1 else None
    
    print("\\n=== Test Case 3: Failed login with wrong password ===")
    print(Lse55.do_login("user1", "wrongpass"))
    
    print("\\n=== Test Case 4: Access index and user page ===")
    print(Lse55.index(session_id1))
    print(Lse55.user_page(session_id1))
    
    print("\\n=== Test Case 5: Admin login and access admin page ===")
    session2 = Lse55.do_login("admin", "admin123")
    print(session2)
    session_id2 = session2.split("Session: ")[1] if "Session:" in session2 else None
    print(Lse55.admin_page(session_id2))
    print("User trying to access admin page:")
    print(Lse55.admin_page(session_id1))


if __name__ == "__main__":
    main()
