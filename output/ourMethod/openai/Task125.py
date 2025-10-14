from typing import Dict, Set, Tuple

GENERIC_ERROR = "ERROR: Access denied or resource not found."

ALLOWED_ROLES: Set[str] = {"guest", "user", "admin"}

RESOURCES: Dict[str, Tuple[str, Set[str]]] = {
    "public": ("Welcome to the public area.", {"guest", "user", "admin"}),
    "dashboard": ("Admin control panel.", {"admin"}),
    "profile": ("User profile page.", {"user", "admin"}),
    "report2025": ("Confidential report 2025.", {"user", "admin"}),
    "help": ("Help and FAQs.", {"guest", "user", "admin"}),
}


def _is_valid_role(role: str) -> bool:
    return isinstance(role, str) and role in ALLOWED_ROLES


def _is_valid_resource_id(resource_id: str) -> bool:
    if not isinstance(resource_id, str):
        return False
    if not (1 <= len(resource_id) <= 20):
        return False
    for ch in resource_id:
        if not (ch.isalnum() or ch in "_-"):
            return False
    return True


def access_resource(role: str, resource_id: str) -> str:
    if not _is_valid_role(role) or not _is_valid_resource_id(resource_id):
        return GENERIC_ERROR
    entry = RESOURCES.get(resource_id)
    if entry is None:
        return GENERIC_ERROR
    content, allowed_roles = entry
    if role not in allowed_roles:
        return GENERIC_ERROR
    return content


if __name__ == "__main__":
    tests = [
        ("admin", "dashboard"),
        ("guest", "public"),
        ("user", "report2025"),
        ("guest", "report2025"),
        ("user", "bad$id"),
    ]
    for i, (r, res) in enumerate(tests, 1):
        print(f"Test {i} ({r}, {res}): {access_resource(r, res)}")