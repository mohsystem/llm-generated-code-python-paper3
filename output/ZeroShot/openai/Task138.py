from enum import Enum, auto
from threading import RLock
from typing import Set, Dict

class Permission(Enum):
    READ = auto()
    WRITE = auto()
    DELETE = auto()
    EXECUTE = auto()
    ADMIN = auto()

class Role(Enum):
    GUEST = auto()
    USER = auto()
    MODERATOR = auto()
    ADMINISTRATOR = auto()

ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.GUEST: {Permission.READ},
    Role.USER: {Permission.READ, Permission.WRITE},
    Role.MODERATOR: {Permission.READ, Permission.WRITE, Permission.DELETE},
    Role.ADMINISTRATOR: {Permission.READ, Permission.WRITE, Permission.DELETE, Permission.EXECUTE, Permission.ADMIN},
}

def sanitize_name(input_str: str) -> str:
    if input_str is None:
        return ""
    trimmed = input_str.strip()
    out = []
    for ch in trimmed:
        if ch.isalnum() or ch in "_.-":
            out.append(ch)
        if len(out) >= 64:
            break
    return "".join(out)

class User:
    __slots__ = ("username", "_roles", "_direct_permissions")

    def __init__(self, username: str):
        self.username = username
        self._roles: Set[Role] = set()
        self._direct_permissions: Set[Permission] = set()

    @property
    def roles(self) -> Set[Role]:
        return set(self._roles)

    @property
    def direct_permissions(self) -> Set[Permission]:
        return set(self._direct_permissions)

class PermissionManager:
    def __init__(self):
        self._users: Dict[str, User] = {}
        self._lock = RLock()

    def create_user(self, raw_username: str) -> bool:
        username = sanitize_name(raw_username)
        if not username:
            return False
        with self._lock:
            if username in self._users:
                return False
            self._users[username] = User(username)
            return True

    def delete_user(self, raw_username: str) -> bool:
        username = sanitize_name(raw_username)
        with self._lock:
            return self._users.pop(username, None) is not None

    def assign_role(self, raw_username: str, role: Role) -> bool:
        username = sanitize_name(raw_username)
        if role is None:
            return False
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            if role in user._roles:
                return False
            user._roles.add(role)
            return True

    def revoke_role(self, raw_username: str, role: Role) -> bool:
        username = sanitize_name(raw_username)
        if role is None:
            return False
        with self._lock:
            user = self._users.get(username)
            if not user or role not in user._roles:
                return False
            user._roles.remove(role)
            return True

    def grant_permission(self, raw_username: str, perm: Permission) -> bool:
        username = sanitize_name(raw_username)
        if perm is None:
            return False
        with self._lock:
            user = self._users.get(username)
            if not user or perm in user._direct_permissions:
                return False
            user._direct_permissions.add(perm)
            return True

    def revoke_permission(self, raw_username: str, perm: Permission) -> bool:
        username = sanitize_name(raw_username)
        if perm is None:
            return False
        with self._lock:
            user = self._users.get(username)
            if not user or perm not in user._direct_permissions:
                return False
            user._direct_permissions.remove(perm)
            return True

    def has_permission(self, raw_username: str, perm: Permission) -> bool:
        username = sanitize_name(raw_username)
        if perm is None:
            return False
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            if perm in user._direct_permissions:
                return True
            for r in user._roles:
                if perm in ROLE_PERMISSIONS.get(r, set()):
                    return True
            return False

    def list_effective_permissions(self, raw_username: str) -> Set[Permission]:
        username = sanitize_name(raw_username)
        with self._lock:
            user = self._users.get(username)
            if not user:
                return set()
            eff = set(user._direct_permissions)
            for r in user._roles:
                eff |= ROLE_PERMISSIONS.get(r, set())
            return eff

    def list_users(self) -> Set[str]:
        with self._lock:
            return set(self._users.keys())

if __name__ == "__main__":
    pm = PermissionManager()

    # Test 1
    print("Test 1:")
    print(pm.create_user("alice"))
    print(pm.assign_role("alice", Role.USER))
    print(pm.has_permission("alice", Permission.READ))
    print(pm.has_permission("alice", Permission.DELETE))

    # Test 2
    print("Test 2:")
    print(pm.grant_permission("alice", Permission.WRITE))
    print(pm.has_permission("alice", Permission.WRITE))
    print(pm.list_effective_permissions("alice"))

    # Test 3
    print("Test 3:")
    print(pm.create_user("bob"))
    print(pm.assign_role("bob", Role.ADMINISTRATOR))
    print(pm.has_permission("bob", Permission.ADMIN))
    print(pm.has_permission("bob", Permission.DELETE))
    print(pm.list_effective_permissions("bob"))

    # Test 4
    print("Test 4:")
    print(pm.revoke_permission("alice", Permission.WRITE))
    print(pm.has_permission("alice", Permission.WRITE))
    print(pm.list_effective_permissions("alice"))

    # Test 5
    print("Test 5:")
    print(pm.create_user("  Eve!!  "))
    print(pm.create_user("Eve"))
    print(pm.list_users())