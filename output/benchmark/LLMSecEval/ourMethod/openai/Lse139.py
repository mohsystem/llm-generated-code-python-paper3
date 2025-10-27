import os
import re
from typing import Tuple, Optional
from urllib.parse import urlparse, unquote

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

def _is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 1 or len(username) > 64:
        return False
    return USERNAME_RE.match(username) is not None

def _get_db_connection():
    """
    Returns a tuple (conn, placeholder), where placeholder is either '%s' or '?'
    depending on the driver, to be used for parameterized queries.
    """
    db_url = os.getenv("DB_URL")
    db_user = os.getenv("DB_USER")
    db_pass = os.getenv("DB_PASSWORD")

    if not db_url:
        raise RuntimeError("Database URL not set in environment")

    parsed = urlparse(db_url)
    scheme = (parsed.scheme or "").lower()

    # Normalize credentials: prefer URL credentials, else env.
    url_user = unquote(parsed.username) if parsed.username else None
    url_pass = unquote(parsed.password) if parsed.password else None
    user = url_user if url_user else db_user
    password = url_pass if url_pass else db_pass

    # Postgres
    if scheme in ("postgres", "postgresql"):
        conn = None
        # Prefer psycopg (v3), fallback to psycopg2
        try:
            import psycopg
            # psycopg supports direct URI; pass user/password if needed
            if user is not None and password is not None and ("@" not in db_url or ":" not in db_url.split("@")[0]):
                conn = psycopg.connect(db_url, user=user, password=password, connect_timeout=10)
            else:
                conn = psycopg.connect(db_url, connect_timeout=10)
        except Exception:
            try:
                import psycopg2
                if user is not None and password is not None and ("@" not in db_url or ":" not in db_url.split("@")[0]):
                    conn = psycopg2.connect(db_url, user=user, password=password, connect_timeout=10)
                else:
                    conn = psycopg2.connect(db_url, connect_timeout=10)
            except Exception as e2:
                raise RuntimeError("Database connection failed") from e2
        return conn, "%s"

    # MySQL
    if scheme in ("mysql", "mysql+pymysql"):
        try:
            import pymysql
        except Exception as e:
            raise RuntimeError("Database driver not available") from e

        host = parsed.hostname or "localhost"
        port = parsed.port or 3306
        dbname = (parsed.path[1:] if parsed.path.startswith("/") else parsed.path) or None

        # Enforce that user/password must come from env or URL
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user or "",
            password=password or "",
            database=dbname,
            charset="utf8mb4",
            ssl_disabled=False,
            connect_timeout=10,
            read_timeout=10,
            write_timeout=10,
            autocommit=True,
        )
        return conn, "%s"

    # SQLite (allowed for local testing; credentials not used by driver)
    if scheme in ("sqlite", "sqlite3"):
        import sqlite3
        # netloc may be empty; combine netloc and path
        db_path = parsed.path
        if parsed.netloc:
            db_path = f"//{parsed.netloc}{parsed.path}"
        if db_path.startswith("/") and db_path != "/:memory:":
            db_path = db_path
        elif db_path == "/:memory:" or parsed.path == ":memory:":
            db_path = ":memory:"
        else:
            db_path = parsed.path.lstrip("/")
        conn = sqlite3.connect(db_path, timeout=10, isolation_level=None, check_same_thread=False)
        return conn, "?"

    raise RuntimeError("Unsupported DB scheme in DB_URL")

def is_user_moderator(username: str) -> bool:
    if not _is_valid_username(username):
        return False
    try:
        conn, placeholder = _get_db_connection()
    except Exception:
        return False

    # Build query compatible with placeholder
    # Use role column primarily; also check is_moderator where available.
    sql = f"SELECT 1 FROM users WHERE username = {placeholder} AND (" \
          f"LOWER(role) = 'moderator' OR is_moderator IN (1, TRUE)) LIMIT 1"

    try:
        with conn:
            if hasattr(conn, "cursor"):
                cursor = conn.cursor()
            else:
                cursor = conn.cursor()  # fallback, though it's unclear why you check this if both are the same

            with cursor as cur:
                cur.execute(sql, (username,))
                row = cur.fetchone()
                return bool(row)
    except Exception:
        return False

    finally:
        try:
            conn.close()
        except Exception:
            pass

def _main():
    tests = ["alice", "bob", "charlie", "dave", "eve"]
    for t in tests:
        print(f"{t} -> {is_user_moderator(t)}")

if __name__ == "__main__":
    _main()