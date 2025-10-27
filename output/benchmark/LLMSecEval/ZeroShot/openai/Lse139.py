import os
import sys
from typing import Optional

def is_moderator(username: str) -> bool:
    if username is None:
        raise ValueError("username cannot be None")

    host = _get_env_or_raise("DB_HOST")
    port = os.environ.get("DB_PORT", "5432")
    db   = _get_env_or_raise("DB_NAME")
    user = _get_env_or_raise("DB_USER")
    pwd  = _get_env_or_raise("DB_PASSWORD")
    sslmode = os.environ.get("DB_SSLMODE", "prefer")

    # Use psycopg2 for PostgreSQL
    try:
        import psycopg2
        import psycopg2.extras
    except Exception:
        raise RuntimeError("psycopg2 is required")

    conn = None
    try:
        conn_str = f"host={host} port={port} dbname={db} user={user} password={pwd} sslmode={sslmode} connect_timeout=5"
        conn = psycopg2.connect(conn_str)
        conn.set_session(readonly=True, autocommit=True)
        with conn.cursor() as cur:
            try:
                cur.execute("SET statement_timeout = %s", (5000,))
            except Exception:
                pass  # ignore if not supported
            cur.execute("SELECT is_moderator FROM users WHERE username = %s LIMIT 1", (username,))
            row = cur.fetchone()
            if not row:
                return False
            val = row[0]
            if isinstance(val, bool):
                return val
            if val is None:
                return False
            s = str(val).strip().lower()
            return s in ("t", "true", "1", "yes")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

def _get_env_or_raise(key: str) -> str:
    v = os.environ.get(key)
    if not v:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return v

if __name__ == "__main__":
    tests = ["alice", "bob", "charlie", "diana", "eve"]
    for u in tests:
        try:
            print(f"User {u} moderator? {is_moderator(u)}")
        except Exception as e:
            print(f"Error checking user {u}: {e}", file=sys.stderr)