import http.server
import socketserver
import threading
from typing import Optional


class DbConfig:
    def __init__(self, server: str, database: str, user: str, password: str):
        self.server = server
        self.database = database
        self.user = user
        self.password = password


class DbConnection:
    def __init__(self, server: str, database: str, user: str, connected: bool):
        self.server = server
        self.database = database
        self.user = user
        self.connected = connected

    def __repr__(self):
        return f"DbConnection(server='{self.server}', database='{self.database}', user='{self.user}', connected={self.connected})"


class SimpleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Hello from Python web app"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress default logging for cleanliness
        pass


def create_web_app(port: int) -> socketserver.TCPServer:
    server = socketserver.TCPServer(("127.0.0.1", port), SimpleHandler)
    return server


def get_server_name(config: DbConfig) -> str:
    return config.server


def get_database_name(config: DbConfig) -> str:
    return config.database


def get_database_user(config: DbConfig) -> str:
    return config.user


def get_database_password(config: DbConfig) -> str:
    return config.password


def get_database_connection(config: DbConfig) -> DbConnection:
    return DbConnection(config.server, config.database, config.user, True)


if __name__ == "__main__":
    cfg = DbConfig("localhost", "sampledb", "admin", "secret")

    # Test case 1: Server name
    print("Server Name:", get_server_name(cfg))

    # Test case 2: Database name
    print("Database Name:", get_database_name(cfg))

    # Test case 3: Database user
    print("Database User:", get_database_user(cfg))

    # Test case 4: Database password
    print("Database Password:", get_database_password(cfg))

    # Test case 5: Database connection
    conn = get_database_connection(cfg)
    print("Database Connection:", conn)

    # Start web app briefly in a background thread for demo
    srv = create_web_app(9091)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print("Python web app started on http://127.0.0.1:9091/")
    srv.shutdown()
    srv.server_close()
    print("Python web app stopped.")