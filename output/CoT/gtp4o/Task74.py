# Chain-of-Through:
# 1) Problem: Provide a function to create and return a psycopg2 PostgreSQL connection.
# 2) Security: No hardcoded secrets; avoid printing credentials; use SSL by default; set timeouts.
# 3) Secure coding: Pass parameters explicitly to connect(); set sslmode; reasonable connect_timeout; application_name.
# 4) Review: Ensure exceptions don't leak secrets; close connections in tests.
# 5) Output: Final secure function, with 5 test cases.

import os
from typing import Optional

try:
    import psycopg2
    from psycopg2.extensions import connection as Psycopg2Connection
except Exception as e:
    # If psycopg2 is not installed, define a placeholder type to avoid NameError in annotations.
    Psycopg2Connection = object  # type: ignore

def get_postgres_connection(
    host: str,
    port: int,
    database: str,
    user: str,
    password: Optional[str],
    require_ssl: bool = True,
    connect_timeout: int = 5
) -> "Psycopg2Connection":
    if not host:
        raise ValueError("host must not be empty")
    if not database:
        raise ValueError("database must not be empty")
    if not user:
        raise ValueError("user must not be empty")
    if not (1 <= port <= 65535):
        raise ValueError("port must be in range 1..65535")
    timeout = max(1, int(connect_timeout))
    sslmode = "require" if require_ssl else "prefer"

    conn = psycopg2.connect(
        host=host,
        port=port,
        dbname=database,
        user=user,
        password=password,
        connect_timeout=timeout,
        sslmode=sslmode,
        application_name="Task74App",
    )
    return conn

def _run_test(label, host, port, db, user, password, require_ssl, timeout):
    print(f"Test: {label}")
    conn = None
    try:
        conn = get_postgres_connection(host, port, db, user, password, require_ssl, timeout)
        print("  Connection established successfully")
    except Exception as e:
        print(f"  Failed to connect: {type(e).__name__} - {e}")
    finally:
        if conn is not None:
            try:
                conn.close()
                print("  Connection closed")
            except Exception as e:
                print(f"  Failed to close connection: {e}")

if __name__ == "__main__":
    env_user = os.getenv("PGUSER", "postgres")
    env_pass = os.getenv("PGPASSWORD", "")
    # 5 test cases (these may fail depending on the environment)
    _run_test("Local default (SSL required, short timeout)", "127.0.0.1", 5432, "postgres", env_user, env_pass, True, 2)
    _run_test("Invalid port", "127.0.0.1", 1, "postgres", env_user, env_pass, True, 2)
    _run_test("Invalid host", "no-such-host.invalid", 5432, "postgres", env_user, env_pass, True, 2)
    _run_test("Non-SSL prefer", "localhost", 5432, "postgres", env_user, env_pass, False, 2)
    _run_test("Custom DB name", "localhost", 5432, "mydb", env_user, env_pass, True, 2)