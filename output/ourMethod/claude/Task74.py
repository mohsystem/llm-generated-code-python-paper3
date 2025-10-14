import os
from typing import Optional
import psycopg2
from psycopg2 import sql

MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_POSTGRES_PORT = 5432


def create_postgres_connection(
        host: str,
        port: int,
        database: str,
        username: str,
        password: str
) -> psycopg2.extensions.connection:
    if not host or not isinstance(host, str) or not host.strip():
        raise ValueError("Host cannot be None or empty")

    if not database or not isinstance(database, str) or not database.strip():
        raise ValueError("Database name cannot be None or empty")

    if not username or not isinstance(username, str) or not username.strip():
        raise ValueError("Username cannot be None or empty")

    if password is None or not isinstance(password, str):
        raise ValueError("Password cannot be None")

    if not isinstance(port, int) or port < MIN_PORT or port > MAX_PORT:
        raise ValueError(f"Port must be an integer between {MIN_PORT} and {MAX_PORT}")

    sanitized_host = host.strip()
    sanitized_database = database.strip()
    sanitized_username = username.strip()

    if '/' in sanitized_host or '\\' in sanitized_host:
        raise ValueError("Invalid characters in host")

    if '/' in sanitized_database or '\\' in sanitized_database:
        raise ValueError("Invalid characters in database name")

    try:
        connection = psycopg2.connect(
            host=sanitized_host,
            port=port,
            database=sanitized_database,
            user=sanitized_username,
            password=password,
            sslmode='require',
            connect_timeout=10
        )
        return connection
    except psycopg2.Error as e:
        raise ConnectionError(f"Failed to connect to database: {str(e)}")


def main() -> None:
    print("Test 1: Valid connection parameters")
    try:
        conn = create_postgres_connection(
            host=os.getenv("DB_HOST", "localhost"),
            port=DEFAULT_POSTGRES_PORT,
            database=os.getenv("DB_NAME", "testdb"),
            username=os.getenv("DB_USER", "testuser"),
            password=os.getenv("DB_PASSWORD", "testpass")
        )
        print("Connection created successfully (will fail without real DB)")
        if conn:
            conn.close()
    except Exception as e:
        print(f"Expected: {type(e).__name__}")

    print("\nTest 2: None host")
    try:
        create_postgres_connection(None, DEFAULT_POSTGRES_PORT, "testdb", "user", "pass")
        print("FAIL: Should raise exception")
    except (ValueError, TypeError) as e:
        print(f"PASS: {str(e)}")
    except Exception as e:
        print(f"FAIL: Wrong exception type - {type(e).__name__}")

    print("\nTest 3: Invalid port")
    try:
        create_postgres_connection("localhost", 99999, "testdb", "user", "pass")
        print("FAIL: Should raise exception")
    except ValueError as e:
        print(f"PASS: {str(e)}")
    except Exception as e:
        print(f"FAIL: Wrong exception type - {type(e).__name__}")

    print("\nTest 4: Empty database name")
    try:
        create_postgres_connection("localhost", DEFAULT_POSTGRES_PORT, "", "user", "pass")
        print("FAIL: Should raise exception")
    except ValueError as e:
        print(f"PASS: {str(e)}")
    except Exception as e:
        print(f"FAIL: Wrong exception type - {type(e).__name__}")

    print("\nTest 5: None password")
    try:
        create_postgres_connection("localhost", DEFAULT_POSTGRES_PORT, "testdb", "user", None)
        print("FAIL: Should raise exception")
    except (ValueError, TypeError) as e:
        print(f"PASS: {str(e)}")
    except Exception as e:
        print(f"FAIL: Wrong exception type - {type(e).__name__}")


if __name__ == "__main__":
    main()
