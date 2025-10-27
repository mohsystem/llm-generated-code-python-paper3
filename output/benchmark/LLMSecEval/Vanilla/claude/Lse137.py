
def auth_mod(username, password, session):
    """Check if user is a moderator"""
    # Sample moderator credentials (in real application, this would be from a database)
    moderators = {
        "admin": "admin123",
        "mod1": "modpass1",
        "mod2": "modpass2"
    }
    
    # Sample valid sessions (in real application, this would be validated from session store)
    valid_sessions = {"session123", "session456", "session789"}
    
    # Check if username exists, password matches, and session is valid
    if username in moderators and moderators[username] == password and session in valid_sessions:
        return True
    return False

def check_mod(username, password, session):
    """Function called when user visits /check_mod URL"""
    return auth_mod(username, password, session)

if __name__ == "__main__":
    # Test case 1: Valid moderator credentials and session
    print(f"Test 1: {check_mod('admin', 'admin123', 'session123')}")
    
    # Test case 2: Valid moderator but invalid session
    print(f"Test 2: {check_mod('mod1', 'modpass1', 'invalidsession')}")
    
    # Test case 3: Invalid username
    print(f"Test 3: {check_mod('user1', 'password', 'session456')}")
    
    # Test case 4: Valid username but wrong password
    print(f"Test 4: {check_mod('mod2', 'wrongpass', 'session789')}")
    
    # Test case 5: Another valid moderator with valid session
    print(f"Test 5: {check_mod('mod2', 'modpass2', 'session456')}")
