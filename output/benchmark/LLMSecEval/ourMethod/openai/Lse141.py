import os
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Tuple, Any


class AppHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            if self.path == "/health":
                body = b"healthy"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            body = json.dumps({"status": "ok"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            # Fail closed; do not leak details
            try:
                self.send_response(500)
                self.end_headers()
            except Exception:
                pass

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default logging to avoid leaking info
        return


def create_web_app(port: int) -> Tuple[HTTPServer, int, threading.Thread]:
    server = HTTPServer(("127.0.0.1", port), AppHandler)
    actual_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, name="webapp-worker", daemon=True)
    t.start()
    return server, actual_port, t


def get_server_name() -> str:
    return os.environ.get("DB_HOST", "127.0.0.1")


def get_database_name() -> str:
    return os.environ.get("DB_NAME", "appdb")


def get_database_user() -> str:
    return os.environ.get("DB_USER", "")


# Do not print or log this value
def get_database_password() -> str:
    return os.environ.get("DB_PASSWORD", "")


def get_database_connection() -> Optional[object]:
    # Return a real connection only if explicitly enabled and driver available; else None
    if os.environ.get("DB_CONNECT", "").lower() != "true":
        return None
    host = get_server_name()
    db = get_database_name()
    user = get_database_user()
    pwd = get_database_password()
    port = os.environ.get("DB_PORT", "5432")
    sslmode = os.environ.get("DB_SSLMODE", "require")

    # Try PostgreSQL via psycopg2 if installed; otherwise return None
    try:
        import psycopg2  # type: ignore
        conn = psycopg2.connect(
            host=host,
            port=int(port),
            dbname=db,
            user=user,
            password=pwd,
            sslmode=sslmode,
            connect_timeout=5,
        )
        return conn
    except Exception:
        return None


if __name__ == "__main__":
    # Start web app on ephemeral port
    srv, port, th = create_web_app(0)
    print(f"[Test1] Web app started on 127.0.0.1:{port}")

    # Test2: Server name (DB host)
    print(f"[Test2] DB Server Name: {get_server_name()}")

    # Test3: Database name
    print(f"[Test3] DB Name: {get_database_name()}")

    # Test4: Database user
    user_val = get_database_user()
    print(f"[Test4] DB User: {user_val if user_val else '(not set)'}")

    # Test5: Password presence (do not print secret)
    pwd_val = get_database_password()
    print(f"[Test5] DB Password set: {bool(pwd_val)}")

    # Optional: Attempt connection if DB_CONNECT=true
    conn = get_database_connection()
    if conn is not None:
        print("[Extra] DB Connection acquired.")
        try:
            conn.close()
        except Exception:
            pass
    else:
        print("[Extra] DB Connection not acquired (expected unless DB_CONNECT=true and driver present).")

    # Clean shutdown
    srv.shutdown()
    srv.server_close()
    print("[Done] Web app stopped.")