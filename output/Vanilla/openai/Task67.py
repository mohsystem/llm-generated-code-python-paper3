import sqlite3
import json
from dataclasses import dataclass, asdict
import sys

@dataclass
class Customer:
    id: int
    customerusername: str
    name: str
    email: str
    phone: str
    address: str

def init_database():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE customer (
            id INTEGER PRIMARY KEY,
            customerusername TEXT UNIQUE,
            name TEXT,
            email TEXT,
            phone TEXT,
            address TEXT
        )
    """)
    customers = [
        (1, "alice", "Alice Johnson", "alice@example.com", "111-222-3333", "123 Maple St"),
        (2, "bob", "Bob Smith", "bob@example.com", "222-333-4444", "456 Oak Ave"),
        (3, "charlie", "Charlie Lee", "charlie@example.com", "333-444-5555", "789 Pine Rd"),
        (4, "diana", "Diana Prince", "diana@example.com", "444-555-6666", "101 Cedar Blvd"),
        (5, "eric", "Eric Yang", "eric@example.com", "555-666-7777", "202 Birch Ln"),
    ]
    cur.executemany("INSERT INTO customer VALUES (?, ?, ?, ?, ?, ?)", customers)
    conn.commit()
    return conn

def get_customer_by_username(conn, customerusername):
    cur = conn.cursor()
    cur.execute("SELECT id, customerusername, name, email, phone, address FROM customer WHERE customerusername = ?", (customerusername,))
    row = cur.fetchone()
    if row:
        return Customer(*row)
    return None

def main():
    conn = init_database()
    if len(sys.argv) > 1:
        c = get_customer_by_username(conn, sys.argv[1])
        print(json.dumps(asdict(c)) if c else "null")
        return

    tests = ["alice", "bob", "charlie", "diana", "unknown"]
    for u in tests:
        c = get_customer_by_username(conn, u)
        print(json.dumps(asdict(c)) if c else "null")

if __name__ == "__main__":
    main()