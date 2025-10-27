
from enum import Enum
from typing import Optional

class UserRole(Enum):
    """Enum to represent user roles"""
    GUEST = 0
    USER = 1
    ADMIN = 2

class UserSession:
    """Class to represent a user session"""
    def __init__(self, is_logged_in: bool, role: UserRole, username: Optional[str]):
        self._is_logged_in = is_logged_in
        self._role = role
        self._username = username
    
    def is_logged_in(self) -> bool:
        return self._is_logged_in
    
    def get_role(self) -> UserRole:
        return self._role
    
    def get_username(self) -> Optional[str]:
        return self._username

def determine_redirect_page(session: Optional[UserSession]) -> str:
    """\n    Determines the redirect page based on user session\n    \n    Args:\n        session: The user session object\n        \n    Returns:\n        The page to redirect to\n    """
    # Input validation
    if session is None:
        return "/login"
    
    # Check if user is not logged in
    if not session.is_logged_in():
        return "/login"
    
    # Check if user is admin
    if session.get_role() == UserRole.ADMIN:
        return "/admin"
    
    # Check if user is a regular user
    if session.get_role() == UserRole.USER:
        return "/user"
    
    # Default fallback to login
    return "/login"

if __name__ == "__main__":
    # Test case 1: Not logged in
    session1 = UserSession(False, UserRole.GUEST, None)
    print(f"Test 1 - Not logged in: {determine_redirect_page(session1)}")
    
    # Test case 2: Logged in as regular user
    session2 = UserSession(True, UserRole.USER, "john_doe")
    print(f"Test 2 - Regular user: {determine_redirect_page(session2)}")
    
    # Test case 3: Logged in as admin
    session3 = UserSession(True, UserRole.ADMIN, "admin_user")
    print(f"Test 3 - Admin user: {determine_redirect_page(session3)}")
    
    # Test case 4: Null session
    session4 = None
    print(f"Test 4 - Null session: {determine_redirect_page(session4)}")
    
    # Test case 5: Logged in but with GUEST role
    session5 = UserSession(True, UserRole.GUEST, "guest_user")
    print(f"Test 5 - Logged in guest: {determine_redirect_page(session5)}")
