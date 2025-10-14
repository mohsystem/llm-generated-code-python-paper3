from typing import Dict

# Role hierarchy and resources
ROLE_LEVEL: Dict[str, int] = {
    "guest": 0,
    "user": 1,
    "editor": 2,
    "admin": 3,
}

RESOURCE_REQUIRED_LEVEL: Dict[str, int] = {
    "public:news": 0,
    "content:view": 1,
    "user:profile": 1,
    "content:edit": 2,
    "admin:dashboard": 3,
    "reports:financial": 3,
}

RESOURCE_CONTENT: Dict[str, str] = {
    "public:news": "Top headlines for everyone",
    "content:view": "Catalog of articles",
    "user:profile": "Personal profile details",
    "content:edit": "Editor panel for articles",
    "admin:dashboard": "System metrics and controls",
    "reports:financial": "Quarterly financial report",
}

def access_resource(user: str, role: str, resource_id: str) -> str:
    if role is None or resource_id is None:
        return "ACCESS DENIED: Invalid input"
    user_level = ROLE_LEVEL.get(role.lower())
    if user_level is None:
        return "ACCESS DENIED: Unknown role"
    required_level = RESOURCE_REQUIRED_LEVEL.get(resource_id)
    if required_level is None:
        return "ACCESS DENIED: Unknown resource"
    if user_level >= required_level:
        content = RESOURCE_CONTENT.get(resource_id, "(no content)")
        return f"ACCESS GRANTED: {resource_id} -> {content}"
    return "ACCESS DENIED: Insufficient permissions"

if __name__ == "__main__":
    tests = [
        ("alice", "guest", "public:news"),
        ("bob", "user", "content:view"),
        ("cindy", "user", "admin:dashboard"),
        ("dave", "editor", "content:edit"),
        ("erica", "guest", "user:profile"),
    ]
    for t in tests:
        print(access_resource(*t))