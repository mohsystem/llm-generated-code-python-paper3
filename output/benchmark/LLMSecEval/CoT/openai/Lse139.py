import os
from typing import Optional

def _get_env(name: str, default: Optional[str]) -> str:
    v = os.getenv(name)
    if v is None or v == "":
        return "" if default is None else default
    return v

def is_moderator(username: str) -> bool:
    host = _get_env("DB_HOST", "localhost")
    port = _get_env("DB_PORT", "5432")
    db   = _get_env("DB_NAME", "postgres")
    user = _get_env("DB_USER", "postgres")
    pwd  = _get_env("DB_PASS", "")

    try:
        import psycopg2
        with psycopg2.connect(host=host, port=port, dbname=db, user=user, password=pwd) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT is_moderator FROM users WHERE username = %s LIMIT 1", (username,))
                row = cur.fetchone()
                if not row:
                    return False
                return bool(row[0])
    except Exception:
        return False

if __name__ == "__main__":
    test_users = ["alice", "bob", "charlie", "diana", "eve"]
    for u in test_users:
        print(f"User: {u} -> {is_moderator(u)}")