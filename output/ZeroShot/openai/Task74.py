import os
import re
import psycopg2
from typing import Optional

def get_postgres_connection(
    host: str,
    port: int,
    dbname: str,
    user: str,
    password: Optional[str] = None,
    sslmode: Optional[str] = None,
    sslrootcert: Optional[str] = None,
    connect_timeout: int = 10
):
    if not _is_valid_hostname(host):
        raise ValueError("Invalid host")
    if not (1 <= port <= 65535):
        raise ValueError("Invalid port")
    if not _is_valid_dbname(dbname):
        raise ValueError("Invalid database name")
    if not user:
        raise ValueError("User is required")
    if connect_timeout < 1 or connect_timeout > 600:
        connect_timeout = 10

    mode = _normalize_sslmode(sslmode)

    conn_kwargs = {
        "host": host,
        "port": port,
        "dbname": dbname,
        "user": user,
        "connect_timeout": connect_timeout,
        "application_name": "Task74",
        "sslmode": mode
    }
    if password is not None:
        conn_kwargs["password"] = password
    if sslrootcert:
        conn_kwargs["sslrootcert"] = sslrootcert

    return psycopg2.connect(**conn_kwargs)

def _is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1]
        return bool(re.fullmatch(r"[0-9A-Fa-f:.]+", inner))
    return bool(re.fullmatch(r"[A-Za-z0-9._-]+", host))

def _is_valid_dbname(db: str) -> bool:
    if not db or len(db) > 63:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_-]+", db))

def _normalize_sslmode(mode: Optional[str]) -> str:
    if not mode:
        return "require"
    m = mode.strip().lower()
    if m in {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}:
        return m
    return "require"

if __name__ == "__main__":
    tests = [
        # host, port, db, user, pass, sslmode, sslrootcert, timeout
        ("localhost", 5432, "postgres", "postgres", "", "require", None, 5),
        ("invalid.localdomain", 5432, "postgres", "postgres", "secret", "require", None, 5),
        ("localhost", 1, "postgres", "postgres", "secret", "require", None, 3),
        ("localhost", 5432, "invalid_db", "postgres", "secret", "require", None, 5),
        (
            os.getenv("PGHOST", "localhost"),
            int(os.getenv("PGPORT", "5432")),
            os.getenv("PGDATABASE", "postgres"),
            os.getenv("PGUSER", "postgres"),
            os.getenv("PGPASSWORD", ""),
            os.getenv("PGSSLMODE", "require"),
            os.getenv("PGSSLROOTCERT"),
            int(os.getenv("PGCONNECT_TIMEOUT", "5"))
        )
    ]
    for i, t in enumerate(tests, start=1):
        try:
            conn = get_postgres_connection(*t)
            conn.close()
            print(f"Test {i}: Connection successful")
        except ValueError as ve:
            print(f"Test {i}: Invalid input - {ve}")
        except Exception as e:
            # Avoid printing sensitive info; psycopg2 may include DSN without password by default
            msg = str(e).replace("password=", "password=REDACTED")
            print(f"Test {i}: Connection failed - {e.__class__.__name__}: {msg}")