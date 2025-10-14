# Minimal high-level comments to reflect secure development lifecycle:
# Implemented with input validation, normalization, and safe data handling.

import re
from typing import Set, Dict

class PermissionManager:
    _NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

    @staticmethod
    def _normalize(value: str) -> str:
        if value is None:
            raise ValueError("None not allowed")
        v = value.strip().lower()
        if not PermissionManager._NAME_PATTERN.fullmatch(v):
            raise ValueError(f"Invalid name: {value}")
        return v

    def __init__(self):
        self._roles: Dict[str, Set[str]] = {}
        self._users_direct: Dict[str, Set[str]] = {}
        self._users_roles: Dict[str, Set[str]] = {}

    def add_role(self, role_name: str) -> bool:
        r = self._normalize(role_name)
        if r in self._roles:
            return False
        self._roles[r] = set()
        return True

    def add_user(self, username: str) -> bool:
        u = self._normalize(username)
        if u in self._users_direct:
            return False
        self._users_direct[u] = set()
        self._users_roles[u] = set()
        return True

    def add_permission_to_role(self, role_name: str, permission: str) -> bool:
        r = self._normalize(role_name)
        p = self._normalize(permission)
        if r not in self._roles:
            return False
        if p in self._roles[r]:
            return False
        self._roles[r].add(p)
        return True

    def remove_permission_from_role(self, role_name: str, permission: str) -> bool:
        r = self._normalize(role_name)
        p = self._normalize(permission)
        if r not in self._roles:
            return False
        if p not in self._roles[r]:
            return False
        self._roles[r].remove(p)
        return True

    def grant_permission_to_user(self, username: str, permission: str) -> bool:
        u = self._normalize(username)
        p = self._normalize(permission)
        if u not in self._users_direct:
            return False
        if p in self._users_direct[u]:
            return False
        self._users_direct[u].add(p)
        return True

    def revoke_permission_from_user(self, username: str, permission: str) -> bool:
        u = self._normalize(username)
        p = self._normalize(permission)
        if u not in self._users_direct or p not in self._users_direct[u]:
            return False
        self._users_direct[u].remove(p)
        return True

    def assign_role_to_user(self, username: str, role_name: str) -> bool:
        u = self._normalize(username)
        r = self._normalize(role_name)
        if u not in self._users_roles or r not in self._roles:
            return False
        if r in self._users_roles[u]:
            return False
        self._users_roles[u].add(r)
        return True

    def unassign_role_from_user(self, username: str, role_name: str) -> bool:
        u = self._normalize(username)
        r = self._normalize(role_name)
        if u not in self._users_roles or r not in self._users_roles[u]:
            return False
        self._users_roles[u].remove(r)
        return True

    def user_has_permission(self, username: str, permission: str) -> bool:
        u = self._normalize(username)
        p = self._normalize(permission)
        if u not in self._users_direct:
            return False
        if p in self._users_direct[u]:
            return True
        for role in self._users_roles.get(u, ()):
            if p in self._roles.get(role, ()):
                return True
        return False

    def get_effective_permissions(self, username: str) -> Set[str]:
        u = self._normalize(username)
        if u not in self._users_direct:
            return set()
        eff = set(self._users_direct[u])
        for r in self._users_roles[u]:
            eff |= self._roles.get(r, set())
        return set(eff)


def main():
    pm = PermissionManager()

    # Test Case 1
    pm.add_role("admin")
    pm.add_permission_to_role("admin", "read")
    pm.add_permission_to_role("admin", "write")
    pm.add_permission_to_role("admin", "delete")
    pm.add_user("alice")
    pm.assign_role_to_user("alice", "admin")
    print("TC1 alice has delete:", pm.user_has_permission("alice", "delete"))

    # Test Case 2
    pm.add_role("editor")
    pm.add_permission_to_role("editor", "write")
    pm.add_user("bob")
    pm.grant_permission_to_user("bob", "read")
    print("TC2 bob has write before role:", pm.user_has_permission("bob", "write"))
    pm.assign_role_to_user("bob", "editor")
    print("TC2 bob has write after role:", pm.user_has_permission("bob", "write"))

    # Test Case 3
    pm.remove_permission_from_role("admin", "delete")
    print("TC3 alice has delete after removal from role:", pm.user_has_permission("alice", "delete"))

    # Test Case 4
    pm.grant_permission_to_user("alice", "delete")
    print("TC4 alice has delete after direct grant:", pm.user_has_permission("alice", "delete"))

    # Test Case 5
    print("TC5 unknown user has read:", pm.user_has_permission("charlie", "read"))
    print("TC5 adding duplicate role 'admin':", pm.add_role("admin"))
    print("TC5 alice effective perms:", sorted(pm.get_effective_permissions("alice")))

if __name__ == "__main__":
    main()