import os
import sqlite3
from typing import Optional
from flask import Flask, jsonify, Response

def get_server_name(default_value: str) -> str:
    v = os.getenv("SERVER_NAME")
    return v if v and v.strip() else default_value

def get_db_name(default_value: str) -> str:
    v = os.getenv("DB_NAME")
    return v if v and v.strip() else default_value

def get_db_user(default_value: str) -> str:
    v = os.getenv("DB_USER")
    return v if v and v.strip() else default_value

def get_db_password(default_value: str) -> str:
    v = os.getenv("DB_PASSWORD")
    return v if v and v.strip() else default_value

def get_db_connection(db_url: str, user: str, password: str) -> Optional[sqlite3.Connection]:
    try:
        if db_url.startswith("sqlite:///"):
            path = db_url.replace("sqlite:///", "", 1)
        else:
            # Only sqlite is supported in this example for zero-dependency
            return None
        # Avoid printing credentials; using only db_url
        conn = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        return conn
    except Exception:
        return None

app = Flask(__name__)

@app.get("/")
def index() -> Response:
    return Response("Lse141 Python web app is running", mimetype="text/plain")

@app.get("/health")
def health():
    return jsonify(status="ok")

@app.get("/config")
def config():
    server_name = get_server_name("localhost")
    db_name = get_db_name("appdb")
    db_user = get_db_user("appuser")
    db_pass = get_db_password("")
    masked = "*" * min(12, len(db_pass))
    return jsonify(
        serverName=server_name,
        dbName=db_name,
        dbUser=db_user,
        dbPasswordMasked=masked
    )

if __name__ == "__main__":
    # 5 test cases
    t1 = get_server_name("localhost")
    t2 = get_db_name("defaultdb")
    t3 = get_db_user("defaultuser")
    t4 = get_db_password("defaultpass")
    t5 = get_db_connection(os.getenv("DB_URL", "sqlite:///./test.db"), t3, t4)

    print(f"Test1 serverName: {t1}")
    print(f"Test2 dbName: {t2}")
    print(f"Test3 dbUser: {t3}")
    print(f"Test4 dbPasswordMasked: {'*' * min(12, len(t4))}")
    print(f"Test5 connection established: {bool(t5)}")

    if t5:
        try:
            t5.close()
        except Exception:
            pass

    port_str = os.getenv("PORT", "5000")
    try:
        port = int(port_str)
        if port < 1024 or port > 65535:
            port = 5000
    except ValueError:
        port = 5000
    app.run(host="0.0.0.0", port=port)