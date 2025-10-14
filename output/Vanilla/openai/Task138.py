class PermissionSystem:
    def __init__(self):
        self.user_roles = {}
        self.role_perms = {}
        self.user_perms = {}

    def _get_or_create(self, m, k):
        if k not in m:
            m[k] = set()
        return m[k]

    def add_user(self, user):
        self._get_or_create(self.user_roles, user)
        self._get_or_create(self.user_perms, user)

    def add_role(self, role):
        self._get_or_create(self.role_perms, role)

    def grant_role_to_user(self, user, role):
        self.add_user(user)
        self.add_role(role)
        self.user_roles[user].add(role)

    def revoke_role_from_user(self, user, role):
        self._get_or_create(self.user_roles, user).discard(role)

    def grant_permission_to_role(self, role, permission):
        self.add_role(role)
        self.role_perms[role].add(permission)

    def revoke_permission_from_role(self, role, permission):
        self._get_or_create(self.role_perms, role).discard(permission)

    def grant_permission_to_user(self, user, permission):
        self.add_user(user)
        self.user_perms[user].add(permission)

    def revoke_permission_from_user(self, user, permission):
        self._get_or_create(self.user_perms, user).discard(permission)

    def has_permission(self, user, permission):
        if permission in self._get_or_create(self.user_perms, user):
            return True
        for role in self._get_or_create(self.user_roles, user):
            if permission in self._get_or_create(self.role_perms, role):
                return True
        return False

    def get_user_permissions(self, user):
        perms = set(self._get_or_create(self.user_perms, user))
        for role in self._get_or_create(self.user_roles, user):
            perms |= self._get_or_create(self.role_perms, role)
        return sorted(perms)


if __name__ == "__main__":
    ps = PermissionSystem()

    # Test 1
    ps.add_role("admin")
    ps.grant_permission_to_role("admin", "read")
    ps.grant_permission_to_role("admin", "write")
    ps.grant_permission_to_role("admin", "delete")
    ps.add_user("alice")
    ps.grant_role_to_user("alice", "admin")
    print("Test1 alice read:", ps.has_permission("alice", "read"))
    print("Test1 alice write:", ps.has_permission("alice", "write"))
    print("Test1 alice delete:", ps.has_permission("alice", "delete"))

    # Test 2
    ps.add_user("bob")
    ps.grant_permission_to_user("bob", "read")
    print("Test2 bob read:", ps.has_permission("bob", "read"))
    print("Test2 bob write:", ps.has_permission("bob", "write"))

    # Test 3
    ps.add_role("editor")
    ps.grant_permission_to_role("editor", "read")
    ps.grant_permission_to_role("editor", "write")
    ps.add_role("viewer")
    ps.grant_permission_to_role("viewer", "read")
    ps.add_user("charlie")
    ps.grant_role_to_user("charlie", "editor")
    ps.grant_role_to_user("charlie", "viewer")
    print("Test3 charlie read:", ps.has_permission("charlie", "read"))
    print("Test3 charlie write:", ps.has_permission("charlie", "write"))

    # Test 4
    ps.grant_role_to_user("bob", "viewer")
    ps.revoke_permission_from_user("bob", "read")
    print("Test4 bob read via role:", ps.has_permission("bob", "read"))
    ps.revoke_role_from_user("bob", "viewer")
    print("Test4 bob read after revoke role:", ps.has_permission("bob", "read"))

    # Test 5
    ps.add_user("dana")
    ps.grant_role_to_user("dana", "editor")
    ps.grant_permission_to_user("dana", "export")
    ps.grant_permission_to_role("editor", "read")
    ps.grant_permission_to_role("editor", "write")
    print("Test5 dana perms:", ps.get_user_permissions("dana"))