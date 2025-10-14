from enum import Enum, auto

class Permission(Enum):
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()
    DELETE = auto()

class User:
    def __init__(self, username):
        self.username = username
        self.permissions = set()

    def grant_permission(self, permission):
        self.permissions.add(permission)

    def revoke_permission(self, permission):
        self.permissions.discard(permission)

    def has_permission(self, permission):
        return permission in self.permissions

class PermissionManager:
    def __init__(self):
        self.users = {}

    def add_user(self, username):
        if username not in self.users:
            self.users[username] = User(username)
            print(f"User '{username}' added.")
        else:
            print(f"User '{username}' already exists.")

    def grant_permission(self, username, permission):
        if username in self.users:
            self.users[username].grant_permission(permission)
            print(f"Permission {permission.name} granted to '{username}'.")
        else:
            print(f"User '{username}' not found.")

    def revoke_permission(self, username, permission):
        if username in self.users:
            self.users[username].revoke_permission(permission)
            print(f"Permission {permission.name} revoked from '{username}'.")
        else:
            print(f"User '{username}' not found.")

    def has_permission(self, username, permission):
        if username in self.users:
            return self.users[username].has_permission(permission)
        return False

    def print_user_permissions(self, username):
        if username in self.users:
            user = self.users[username]
            if not user.permissions:
                print(f"User '{username}' has no permissions.")
            else:
                perms = ", ".join(p.name for p in sorted(list(user.permissions), key=lambda p: p.value))
                print(f"User '{username}' permissions: {perms}")
        else:
            print(f"User '{username}' not found.")

def main():
    manager = PermissionManager()

    print("--- Test Case 1: Add users ---")
    manager.add_user("alice")
    manager.add_user("bob")
    print()

    print("--- Test Case 2: Grant permissions to alice ---")
    manager.grant_permission("alice", Permission.READ)
    manager.grant_permission("alice", Permission.WRITE)
    manager.print_user_permissions("alice")
    manager.print_user_permissions("bob")
    print()

    print("--- Test Case 3: Check alice's permissions ---")
    print(f"Does alice have WRITE permission? {manager.has_permission('alice', Permission.WRITE)}")
    print(f"Does alice have EXECUTE permission? {manager.has_permission('alice', Permission.EXECUTE)}")
    print()

    print("--- Test Case 4: Revoke a permission from alice ---")
    manager.revoke_permission("alice", Permission.WRITE)
    manager.print_user_permissions("alice")
    print()
    
    print("--- Test Case 5: Final permission checks ---")
    print(f"Does alice have WRITE permission now? {manager.has_permission('alice', Permission.WRITE)}")
    print(f"Does alice still have READ permission? {manager.has_permission('alice', Permission.READ)}")
    print(f"Does bob have READ permission? {manager.has_permission('bob', Permission.READ)}")
    manager.grant_permission("bob", Permission.EXECUTE)
    manager.print_user_permissions("bob")

if __name__ == "__main__":
    main()