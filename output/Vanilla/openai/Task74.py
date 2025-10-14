import psycopg2
import psycopg2.extensions

def get_postgres_connection(host: str, port: int, database: str, user: str, password: str) -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=host,
        port=port,
        dbname=database,
        user=user,
        password=password or "",
        connect_timeout=3
    )

def _run_test(label, host, port, database, user, password):
    print(f"Test: {label}")
    conn = None
    try:
        conn = get_postgres_connection(host, port, database, user, password)
        if conn:
            print("  Success: Connected.")
    except Exception as e:
        print(f"  Exception: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

if __name__ == "__main__":
    _run_test("Local default port, default db with empty password", "localhost", 5432, "postgres", "postgres", "")
    _run_test("Local default port with sample credentials", "127.0.0.1", 5432, "postgres", "user", "pass")
    _run_test("Remote host example", "db.example.com", 5432, "mydb", "myuser", "mypass")
    _run_test("Wrong port", "localhost", 6543, "postgres", "postgres", "postgres")
    _run_test("Nonexistent database", "localhost", 5432, "nonexistent", "postgres", "postgres")