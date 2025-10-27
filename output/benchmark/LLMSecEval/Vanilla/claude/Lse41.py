
class UserInfo:
    def __init__(self, username, email, ssn):
        self.username = username
        self.email = email
        self.ssn = ssn
    
    def get_last4_ssn(self):
        if self.ssn and len(self.ssn) >= 4:
            return self.ssn[-4:]
        return "****"

# Mock user database
user_database = {}

def get_info_page(user_id):
    """Simulate /info endpoint"""
    user = user_database.get(user_id)
    if user is None:
        return "User not found"
    
    response = []
    response.append("User Information")
    response.append("================")
    response.append(f"Username: {user.username}")
    response.append(f"Email: {user.email}")
    response.append(f"SSN (Last 4): {user.get_last4_ssn()}")
    
    return "\\n".join(response)

if __name__ == "__main__":
    # Initialize test data
    user_database["user1"] = UserInfo("john_doe", "john@example.com", "123456789")
    user_database["user2"] = UserInfo("jane_smith", "jane@example.com", "987654321")
    user_database["user3"] = UserInfo("bob_wilson", "bob@example.com", "555443333")
    user_database["user4"] = UserInfo("alice_brown", "alice@example.com", "111222333")
    user_database["user5"] = UserInfo("charlie_davis", "charlie@example.com", "999888777")
    
    # Test cases
    print("Test Case 1:")
    print(get_info_page("user1"))
    print()
    
    print("Test Case 2:")
    print(get_info_page("user2"))
    print()
    
    print("Test Case 3:")
    print(get_info_page("user3"))
    print()
    
    print("Test Case 4:")
    print(get_info_page("user4"))
    print()
    
    print("Test Case 5:")
    print(get_info_page("user5"))
