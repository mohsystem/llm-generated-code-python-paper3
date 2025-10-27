import threading
import time
from wsgiref.simple_server import make_server, WSGIServer, WSGIRequestHandler
from http.client import HTTPConnection
from typing import Dict, Optional, Tuple

# In-memory session store: SID -> {username, email, ssn}
SESSIONS: Dict[str, Dict[str, str]] = {}

def info(session: Dict[str, str]) -> Optional[str]:
    username = session.get("username")
    email = session.get("email")
    ssn = session.get("ssn")
    if not username or not email or not ssn:
        return None
    return f"username={username}; email={email}; ssn={ssn}"

def parse_cookies(environ) -> Dict[str, str]:
    raw = environ.get("HTTP_COOKIE", "")
    cookies: Dict[str, str] = {}
    if not raw:
        return cookies
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            cookies[k] = v
    return cookies

def is_valid_sid(sid: str) -> bool:
    if not sid or len(sid) < 8 or len(sid) > 128:
        return False
    return all(c.isalnum() for c in sid)

def app(environ, start_response):
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "GET").upper()
    if path != "/info":
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")])
        return [b"Not Found"]
    if method != "GET":
        start_response("405 Method Not Allowed", [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")])
        return [b"Method Not Allowed"]

    cookies = parse_cookies(environ)
    sid = cookies.get("SID")
    if not sid or not is_valid_sid(sid):
        start_response("401 Unauthorized", [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")])
        return [b"Unauthorized"]

    session = SESSIONS.get(sid)
    if not session:
        start_response("401 Unauthorized", [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")])
        return [b"Unauthorized"]

    body = info(session)
    if body is None:
        start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")])
        return [b"Bad Request"]

    start_response("200 OK", [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")])
    return [body.encode("utf-8")]

def run_server(port: int, ready_evt: threading.Event):
    with make_server("127.0.0.1", port, app, server_class=WSGIServer, handler_class=WSGIRequestHandler) as httpd:
        ready_evt.set()
        httpd.serve_forever()

def http_test(method: str, host: str, port: int, path: str, cookie: Optional[str], expected_status: int, expected_body: Optional[str]) -> bool:
    conn = None
    try:
        conn = HTTPConnection(host, port, timeout=2)
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        status_ok = (resp.status == expected_status)
        body_ok = True
        if expected_body is not None and resp.status == 200:
            data = resp.read().decode("utf-8", "strict")
            body_ok = (data == expected_body)
        else:
            # drain
            _ = resp.read()
        return status_ok and body_ok
    except Exception:
        return False
    finally:
        if conn:
            conn.close()

def main():
    # Populate test sessions
    SID1 = "b7f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"
    SID2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    SID3 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    SESSIONS[SID1] = {"username": "alice", "email": "alice@example.com", "ssn": "123-45-6789"}
    SESSIONS[SID2] = {"username": "bob", "email": "bob@example.com"}  # missing ssn
    SESSIONS[SID3] = {"username": "carol", "email": "carol@example.com", "ssn": "987-65-4321"}

    port = 18095
    ready = threading.Event()
    t = threading.Thread(target=run_server, args=(port, ready), daemon=True)
    t.start()
    ready.wait(2.0)
    time.sleep(0.1)

    host = "127.0.0.1"
    path = "/info"
    total = 5
    passed = 0

    # Test 1: valid SID
    expected1 = "username=alice; email=alice@example.com; ssn=123-45-6789"
    if http_test("GET", host, port, path, f"SID={SID1}", 200, expected1): passed += 1

    # Test 2: missing cookie
    if http_test("GET", host, port, path, None, 401, None): passed += 1

    # Test 3: unknown SID
    if http_test("GET", host, port, path, "SID=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 401, None): passed += 1

    # Test 4: missing ssn
    if http_test("GET", host, port, path, f"SID={SID2}", 400, None): passed += 1

    # Test 5: wrong method
    if http_test("POST", host, port, path, f"SID={SID1}", 405, None): passed += 1

    print(f"Tests passed: {passed}/{total}")

if __name__ == "__main__":
    main()