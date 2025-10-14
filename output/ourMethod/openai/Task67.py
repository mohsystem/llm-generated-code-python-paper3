from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, Optional, List
import json
import sys
import re

@dataclass(frozen=True)
class Customer:
    username: str
    fullName: str
    email: str
    phone: str
    createdAtIso: str

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    # Allow A-Z, a-z, 0-9, '_', '-', '.'
    if not (1 <= len(username.encode('utf-8')) <= 32):
        return False
    return re.fullmatch(r'[A-Za-z0-9_.-]+', username) is not None

def get_customer_by_username(customer_table: Dict[str, Customer], username: str) -> Optional[Customer]:
    if not is_valid_username(username):
        return None
    return customer_table.get(username)

def seed_in_memory_db() -> Dict[str, Customer]:
    db: Dict[str, Customer] = {
        "alice.smith": Customer("alice.smith", "Alice Smith", "alice@example.com", "+1-202-555-0101", "2024-07-01T10:00:00Z"),
        "bob_1984": Customer("bob_1984", "Bob Stone", "bob1984@example.com", "+1-202-555-0102", "2023-12-11T08:45:30Z"),
        "charlie": Customer("charlie", "Charlie Kim", "charlie@example.org", "+44-20-7946-0958", "2022-05-20T15:20:10Z"),
    }
    return db

def to_json(obj: Optional[Customer], username: str) -> str:
    if obj is None:
        return json.dumps({"error": "Customer not found or invalid username", "username": username}, ensure_ascii=False)
    return json.dumps(asdict(obj), ensure_ascii=False)

def main() -> None:
    db = seed_in_memory_db()

    # If a username is provided as command line argument, query it
    if len(sys.argv) > 1:
        uname = sys.argv[1]
        print(to_json(get_customer_by_username(db, uname), uname))

    # 5 test cases
    tests: List[str] = [
        "alice.smith",                         # existing
        "bob_1984",                            # existing
        "invalid user",                        # invalid (space)
        "unknown_user",                        # not existing but valid
        "averylongusername_exceeding_32_chars" # invalid (too long)
    ]
    for t in tests:
        print(to_json(get_customer_by_username(db, t), t))

if __name__ == "__main__":
    main()