import os
import sys

def is_moderator(username: str) -> bool:
    if not username:
        return False
    host = os.environ.get("DB_HOST")
    port = os.environ.get("DB_PORT", "5432")
    db   = os.environ.get("DB_NAME")
    user = os.environ.get("DB_USER")
    pwd  = os.environ.get("DB_PASSWORD")
    if not host or not db or not user:
        return False
    try:
        import psycopg2
        with psycopg2.connect(host=host, port=port, dbname=db, user=user, password=pwd) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT is_moderator FROM users WHERE username = %s LIMIT 1", (username,))
                row = cur.fetchone()
                if row is None:
                    return False
                return bool(row[0])
    except Exception:
        return False

if __name__ == "__main__":
    test_users = ["alice", "bob", "charlie", "dana", "eric"]
    for u in test_users:
        print(f"{u} -> {is_moderator(u)}")