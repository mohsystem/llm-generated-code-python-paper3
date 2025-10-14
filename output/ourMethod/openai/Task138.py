from typing import Dict, Set, List
import re

class AccessManager:
    MAX_NAME_LEN = 64
    MAX_USERS = 10000
    MAX_ROLES = 10000
    MAX_PERMS_PER_ROLE = 1000
    MAX_ROLES_PER_USER = 1000
    NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

    def __init__(self) -> None:
        self.role_to_perms: Dict[str, Set[str]] = {}
        self.user_to_roles: Dict[str, Set[str]] = {}

    def _valid_name(self, name: str) -> bool:
        if not isinstance(name, str):
            return False
        if len(name) < 1 or len(name) > self.MAX_NAME_LEN:
            return False
        return bool(self.NAME_PATTERN.match(name))

    def create_role(self, role: str) -> bool:
        if not self._valid_name(role):
            return False
        if len(self.role_to_perms) >= self.MAX_ROLES:
            return False
        if role in self.role_to_perms:
            return False
        self.role_to_perms[role] = set()
        return True

    def remove_role(self, role: str) -> bool:
        if not self._valid_name(role):
            return False
        if role not in self.role_to_perms:
            return False
        del self.role_to_perms[role]
        for roles in self.user_to_roles.values():
            roles.discard(role)
        return True

    def add_permission_to_role(self, role: str, perm: str) -> bool:
        if not (self._valid_name(role) and self._valid_name(perm)):
            return False
        if role not in self.role_to_perms:
            return False
        perms = self.role_to_perms[role]
        if len(perms) >= self.MAX_PERMS_PER_ROLE:
            return False
        if perm in perms:
            return False
        perms.add(perm)
        return True

    def remove_permission_from_role(self, role: str, perm: str) -> bool:
        if not (self._valid_name(role) and self._valid_name(perm)):
            return False
        if role not in self.role_to_perms:
            return False
        if perm not in self.role_to_perms[role]:
            return False
        self.role_to_perms[role].remove(perm)
        return True

    def create_user(self, user: str) -> bool:
        if not self._valid_name(user):
            return False
        if len(self.user_to_roles) >= self.MAX_USERS:
            return False
        if user in self.user_to_roles:
            return False
        self.user_to_roles[user] = set()
        return True

    def delete_user(self, user: str) -> bool:
        if not self._valid_name(user):
            return False
        return self.user_to_roles.pop(user, None) is not None

    def assign_role_to_user(self, user: str, role: str) -> bool:
        if not (self._valid_name(user) and self._valid_name(role)):
            return False
        if role not in self.role_to_perms:
            return False
        roles = self.user_to_roles.get(user)
        if roles is None:
            return False
        if len(roles) >= self.MAX_ROLES_PER_USER:
            return False
        if role in roles:
            return False
        roles.add(role)
        return True

    def revoke_role_from_user(self, user: str, role: str) -> bool:
        if not (self._valid_name(user) and self._valid_name(role)):
            return False
        roles = self.user_to_roles.get(user)
        if roles is None:
            return False
        if role not in roles:
            return False
        roles.remove(role)
        return True

    def user_has_permission(self, user: str, perm: str) -> bool:
        if not (self._valid_name(user) and self._valid_name(perm)):
            return False
        roles = self.user_to_roles.get(user)
        if roles is None:
            return False
        for r in roles:
            perms = self.role_to_perms.get(r)
            if perms and perm in perms:
                return True
        return False

    def list_user_permissions(self, user: str) -> List[str]:
        if not self._valid_name(user):
            return []
        roles = self.user_to_roles.get(user)
        if roles is None:
            return []
        perms: Set[str] = set()
        for r in roles:
            p = self.role_to_perms.get(r)
            if p:
                perms.update(p)
        return sorted(perms)

    def list_user_roles(self, user: str) -> List[str]:
        if not self._valid_name(user):
            return []
        roles = self.user_to_roles.get(user)
        if roles is None:
            return []
        return sorted(roles)


def main() -> None:
    mgr = AccessManager()
    # Test 1
    print("Test1-CreateRoles:", mgr.create_role("admin") and mgr.create_role("editor"))
    print("Test1-AddPermsAdmin:", mgr.add_permission_to_role("admin", "read_all") and
          mgr.add_permission_to_role("admin", "write_all") and
          mgr.add_permission_to_role("admin", "manage_users"))
    print("Test1-AddPermsEditor:", mgr.add_permission_to_role("editor", "read_articles") and
          mgr.add_permission_to_role("editor", "edit_articles"))
    print("Test1-CreateUsers:", mgr.create_user("alice") and mgr.create_user("bob"))
    print("Test1-AssignRoles:", mgr.assign_role_to_user("alice", "admin") and
          mgr.assign_role_to_user("bob", "editor"))
    print("Test1-CheckPerms:", mgr.user_has_permission("alice", "manage_users") and
          (not mgr.user_has_permission("bob", "manage_users")))

    # Test 2: Invalid names
    print("Test2-InvalidRoleName:", not mgr.create_role("invalid role"))
    print("Test2-InvalidUserName:", not mgr.create_user(""))
    print("Test2-InvalidPermToRole:", not mgr.add_permission_to_role("admin", "bad perm"))

    # Test 3: Duplicates
    print("Test3-DuplicateRole:", not mgr.create_role("admin"))
    print("Test3-DuplicateUser:", not mgr.create_user("alice"))
    print("Test3-DuplicatePermission:", not mgr.add_permission_to_role("admin", "read_all"))

    # Test 4: Revoke role
    print("Test4-RevokeRole:", mgr.revoke_role_from_user("alice", "admin"))
    print("Test4-CheckPermAfterRevoke:", not mgr.user_has_permission("alice", "read_all"))

    # Test 5: Remove permission from role and verify after re-assign
    print("Test5-AddRoleBack:", mgr.assign_role_to_user("alice", "admin"))
    print("Test5-RemovePermFromRole:", mgr.remove_permission_from_role("admin", "write_all"))
    print("Test5-CheckRemovedPerm:", not mgr.user_has_permission("alice", "write_all"))

    # Display perms
    print("AlicePerms:", mgr.list_user_permissions("alice"))
    print("BobPerms:", mgr.list_user_permissions("bob"))

if __name__ == "__main__":
    main()