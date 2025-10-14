import re
from typing import Any, Optional, Tuple

def create_postgres_connection(
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
    use_ssl: bool,
    connect_timeout_seconds: int
) -> Any:
    """
    Create and return a PostgreSQL connection object using psycopg (v3) or psycopg2.
    Raises ValueError for validation issues and ImportError if no driver is available.
    """
    # Validate inputs
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host or ""):
        raise ValueError("Invalid host: must be 1-253 chars of letters, digits, '.', or '-'")
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("Invalid port: must be in range 1-65535")
    if not isinstance(database, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,63}", database or ""):
        raise ValueError("Invalid database name: 1-63 chars of letters, digits, or '_'")
    if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,63}", user or ""):
        raise ValueError("Invalid username: 1-63 chars of letters, digits, or '_'")
    if not isinstance(password, str) or len(password) == 0 or len(password) > 1024:
        raise ValueError("Invalid password: length must be 1-1024")
    if not isinstance(connect_timeout_seconds, int) or connect_timeout_seconds < 1 or connect_timeout_seconds > 600:
        raise ValueError("Invalid connect timeout: must be in range 1-600 seconds")

    driver = None
    connect_fn = None

    try:
        import psycopg  # psycopg v3
        driver = "psycopg"
        connect_fn = psycopg.connect
    except Exception:
        try:
            import psycopg2  # psycopg2
            driver = "psycopg2"
            connect_fn = psycopg2.connect
        except Exception as e:
            raise ImportError("No PostgreSQL driver available (psycopg or psycopg2 not installed)") from e

    sslmode = "require" if use_ssl else "disable"
    # DSN without password (password passed separately) to avoid logging secrets accidentally
    dsn = f"host={host} port={port} dbname={database} user={user} sslmode={sslmode} connect_timeout={connect_timeout_seconds}"

    # Create connection; do not print or log the password
    if driver == "psycopg":
        # psycopg v3 keyword args
        return connect_fn(dsn=dsn, password=password)
    else:
        # psycopg2 supports both dsn string and kwargs
        return connect_fn(dsn=dsn, password=password)


def _run_test(name: str, params: Tuple[Any, ...]) -> None:
    print(f"Test: {name}")
    conn = None
    try:
        conn = create_postgres_connection(*params)
        print(f"Connection created: {type(conn).__name__} (closing immediately)")
    except Exception as e:
        # Avoid printing secrets; error messages typically won't include password
        msg = str(e)
        msg = re.sub("(?i)password", "******", msg)
        print(f"Error: {e.__class__.__name__}: {msg}")
    finally:
        if conn is not None:
            try:
                # psycopg and psycopg2 both implement close()
                conn.close()
            except Exception:
                pass
    print("----")


if __name__ == "__main__":
    # Five test cases
    _run_test(
        "Valid localhost, likely missing driver or DB",
        ("localhost", 5432, "postgres", "postgres", "secret", False, 2)
    )
    _run_test(
        "Invalid host characters",
        ("bad host!", 5432, "postgres", "postgres", "secret", False, 2)
    )
    _run_test(
        "Invalid port",
        ("localhost", 70000, "postgres", "postgres", "secret", True, 2)
    )
    _run_test(
        "Invalid database name (too long)",
        ("localhost", 5432, "this_db_name_is_definitely_way_too_long_for_postgres_limit_which_is_63_chars",
         "postgres", "secret", False, 2)
    )
    _run_test(
        "Valid params with SSL require (may fail if server/driver absent)",
        ("127.0.0.1", 5432, "testdb", "testuser", "topsecret", True, 2)
    )