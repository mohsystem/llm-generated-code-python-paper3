
class Task125:
    def __init__(self):
        self.user_resources = {}
        self.user_credentials = {}
        self.initialize_data()
    
    def initialize_data(self):
        # Initialize user credentials
        self.user_credentials = {
            "admin": "admin123",
            "user1": "pass1",
            "user2": "pass2",
            "guest": "guest123",
            "manager": "manager456"
        }
        
        # Initialize user resources
        self.user_resources = {
            "admin": ["Dashboard", "Users", "Settings", "Reports", "Database"],
            "user1": ["Dashboard", "Profile", "Documents"],
            "user2": ["Dashboard", "Profile", "Messages"],
            "guest": ["Dashboard", "Help"],
            "manager": ["Dashboard", "Reports", "Team", "Projects"]
        }
    
    def authenticate(self, username, password):
        return username in self.user_credentials and \
               self.user_credentials[username] == password
    
    def get_accessible_resources(self, username):
        return self.user_resources.get(username, [])
    
    def can_access_resource(self, username, resource):
        resources = self.get_accessible_resources(username)
        return resource in resources
    
    def access_resource(self, username, password, resource):
        if not self.authenticate(username, password):
            return "Authentication failed: Invalid username or password"
        
        if self.can_access_resource(username, resource):
            return f"Access granted: {username} can access {resource}"
        else:
            return f"Access denied: {username} cannot access {resource}"


def main():
    system = Task125()
    
    print("Test Case 1: Admin accessing Dashboard")
    print(system.access_resource("admin", "admin123", "Dashboard"))
    print()
    
    print("Test Case 2: User1 accessing Documents")
    print(system.access_resource("user1", "pass1", "Documents"))
    print()
    
    print("Test Case 3: Guest trying to access Database")
    print(system.access_resource("guest", "guest123", "Database"))
    print()
    
    print("Test Case 4: Invalid credentials")
    print(system.access_resource("user1", "wrongpass", "Dashboard"))
    print()
    
    print("Test Case 5: Manager accessing Reports")
    print(system.access_resource("manager", "manager456", "Reports"))
    print()
    
    print("Bonus: Listing all accessible resources for user1")
    resources = system.get_accessible_resources("user1")
    print(f"user1 can access: {resources}")


if __name__ == "__main__":
    main()
