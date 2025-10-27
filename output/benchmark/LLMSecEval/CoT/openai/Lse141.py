import sqlite3
from wsgiref.simple_server import make_server

def create_web_app():
    def app(environ, start_response):
        status = '200 OK'
        headers = [('Content-type', 'text/plain; charset=utf-8')]
        start_response(status, headers)
        return [b'Hello from Lse141 web app']
    return app

def get_server_name():
    return "localhost"

def get_database_name():
    return "appdb"

def get_database_user():
    return "appuser"

def get_database_password():
    return "secret"

def get_database_connection(server: str, db: str, user: str, password: str):
    # Using built-in SQLite in-memory DB for a simple, dependency-free connection
    conn = sqlite3.connect(":memory:")
    return conn

if __name__ == "__main__":
    # Prepare tests (5 cases)
    server_name = get_server_name()
    print("Test1 - Server Name:", server_name)

    db_name = get_database_name()
    print("Test2 - Database Name:", db_name)

    db_user = get_database_user()
    print("Test3 - Database User:", db_user)

    db_pass = get_database_password()
    print("Test4 - Database Password (masked):", "*" * len(db_pass))

    conn = get_database_connection(server_name, db_name, db_user, db_pass)
    conn.execute("CREATE TABLE t(x INTEGER);")
    conn.execute("INSERT INTO t(x) VALUES (1);")
    val = conn.execute("SELECT x FROM t").fetchone()[0]
    print("Test5 - DB Connection works, selected:", val)
    conn.close()