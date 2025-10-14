
class Task138:
    def __init__(self):
        self.users = {}
        self.roles = {}
        self.initialize_default_roles()
    
    def initialize_default_roles(self):
        admin = Role("admin")
        admin.add_permission("read")
        admin.add_permission("write")
        admin.add_permission("delete")
        admin.add_permission("execute")
        self.roles["admin"] = admin
        
        editor = Role("editor")
        editor.add_permission("read")
        editor.add_permission("write")
        self.roles["editor"] = editor
        
        viewer = Role("viewer")
        viewer.add_permission("read")
        self.roles["viewer"] = viewer
    
    def add_user(self, username, role_name):
        if username in self.users:
            return False
        role = self.roles.get(role_name)
        if role is None:
            return False
        self.users[username] = User(username, role)
        return True
    
    def remove_user(self, username):
        if username in self.users:
            del self.users[username]
            return True
        return False
    
    def has_permission(self, username, permission):
        user = self.users.get(username)
        if user is None:
            return False
        return user.has_permission(permission)
    
    def assign_role(self, username, role_name):
        user = self.users.get(username)
        role = self.roles.get(role_name)
        if user is None or role is None:
            return False
        user.set_role(role)
        return True
    
    def get_user_permissions(self, username):
        user = self.users.get(username)
        if user is None:
            return set()
        return user.get_permissions()
    
    def add_permission_to_role(self, role_name, permission):
        role = self.roles.get(role_name)
        if role is None:
            return False
        role.add_permission(permission)
        return True
    
    def remove_permission_from_role(self, role_name, permission):
        role = self.roles.get(role_name)
        if role is None:
            return False
        return role.remove_permission(permission)
    
    def get_user_role(self, username):
        user = self.users.get(username)
        if user is None:
            return None
        return user.get_role().get_name()


class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role
    
    def has_permission(self, permission):
        return self.role.has_permission(permission)
    
    def get_permissions(self):
        return self.role.get_permissions()
    
    def get_role(self):
        return self.role
    
    def set_role(self, role):
        self.role = role


class Role:
    def __init__(self, name):
        self.name = name
        self.permissions = set()
    
    def add_permission(self, permission):
        self.permissions.add(permission)
    
    def remove_permission(self, permission):
        if permission in self.permissions:
            self.permissions.remove(permission)
            return True
        return False
    
    def has_permission(self, permission):
        return permission in self.permissions
    
    def get_permissions(self):
        return self.permissions.copy()
    
    def get_name(self):
        return self.name


if __name__ == "__main__":
    system = Task138()
    
    # Test Case 1: Add users with different roles
    print("Test Case 1: Add users")
    print("Add admin user:", system.add_user("john", "admin"))
    print("Add editor user:", system.add_user("jane", "editor"))
    print("Add viewer user:", system.add_user("bob", "viewer"))
    print()
    
    # Test Case 2: Check permissions
    print("Test Case 2: Check permissions")
    print("john has delete permission:", system.has_permission("john", "delete"))
    print("jane has delete permission:", system.has_permission("jane", "delete"))
    print("bob has read permission:", system.has_permission("bob", "read"))
    print("bob has write permission:", system.has_permission("bob", "write"))
    print()
    
    # Test Case 3: Get user permissions
    print("Test Case 3: Get user permissions")
    print("john's permissions:", system.get_user_permissions("john"))
    print("jane's permissions:", system.get_user_permissions("jane"))
    print("bob's permissions:", system.get_user_permissions("bob"))
    print()
    
    # Test Case 4: Change user role
    print("Test Case 4: Change user role")
    print("bob's current role:", system.get_user_role("bob"))
    print("Assign editor role to bob:", system.assign_role("bob", "editor"))
    print("bob's new role:", system.get_user_role("bob"))
    print("bob now has write permission:", system.has_permission("bob", "write"))
    print()
    
    # Test Case 5: Add and remove permissions from role
    print("Test Case 5: Modify role permissions")
    print("Add 'backup' permission to viewer:", system.add_permission_to_role("viewer", "backup"))
    system.add_user("alice", "viewer")
    print("alice has backup permission:", system.has_permission("alice", "backup"))
    print("Remove 'backup' permission from viewer:", system.remove_permission_from_role("viewer", "backup"))
    print("alice still has backup permission:", system.has_permission("alice", "backup"))
