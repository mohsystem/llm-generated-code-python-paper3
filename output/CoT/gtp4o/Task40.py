# Chain-of-Through steps (in comments):
# 1) Problem understanding: Minimal HTTP server serving a settings form (GET) and update (POST) with CSRF protection.
# 2) Security requirements: Session via HttpOnly cookie, SameSite=Strict, CSRF token in session, constant-time compare,
#    safe headers and HTML escaping.
# 3) Secure coding generation: Implement endpoints, session store, token rotation, validation.
# 4) Code review: Validate content types, input sizes, missing/invalid session, rotate tokens after success.
# 5) Secure code output: Final implementation with 5 tests below.

import http.server
import socketserver
import threading
import secrets
import base64
import urllib.parse
import time
from http import HTTPStatus
import http.client
import re

class Task40:
    pass

SESSION_STORE = {}
STORE_LOCK = threading.Lock()

def gen_id(nbytes=32):
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).rstrip(b'=').decode('ascii')

def escape_html(s: str) -> str:
    if s is None:
        return ""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;")
             .replace("/", "&#x2F;"))

def parse_cookies(header: str):
    res = {}
    if not header:
        return res
    parts = header.split(";")
    for p in parts:
        if "=" in p:
            k, v = p.strip().split("=", 1)
            res[k.strip()] = v.strip()
    return res

def set_security_headers(handler: http.server.BaseHTTPRequestHandler):
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Content-Security-Policy",
                        "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'")

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "SecurePythonHTTP/1.0"

    def do_GET(self):
        if self.path == "/":
            self.send_response(302)
            set_security_headers(self)
            self.send_header("Location", "/settings")
            self.end_headers()
            return
        if self.path != "/settings":
            self.send_response(404)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        cookies = parse_cookies(self.headers.get("Cookie"))
        sid = cookies.get("SESSIONID")

        with STORE_LOCK:
            session = SESSION_STORE.get(sid)

            if session is None:
                sid = gen_id()
                session = {"csrf": None, "used": False, "settings": {"displayName": "", "email": ""}}
                SESSION_STORE[sid] = session

            if session["csrf"] is None or session["used"]:
                session["csrf"] = gen_id()
                session["used"] = False

        body = f"""<!doctype html><html><head><meta charset="utf-8"><title>User Settings</title></head>
<body>
<h1>User Settings</h1>
<form method="POST" action="/settings">
<input type="hidden" name="csrf_token" value="{escape_html(session['csrf'])}"/>
<label>Display Name: <input name="displayName" value="{escape_html(session['settings'].get('displayName',''))}"/></label><br/>
<label>Email: <input name="email" value="{escape_html(session['settings'].get('email',''))}"/></label><br/>
<button type="submit">Save</button>
</form>
</body></html>"""

        self.send_response(200)
        set_security_headers(self)
        self.send_header("Set-Cookie", f"SESSIONID={sid}; HttpOnly; Path=/; SameSite=Strict")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        data = body.encode("utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/settings":
            self.send_response(404)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        ctype = self.headers.get("Content-Type", "")
        if not ctype.lower().startswith("application/x-www-form-urlencoded"):
            self.send_response(415)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Unsupported Media Type")
            return

        cookies = parse_cookies(self.headers.get("Cookie"))
        sid = cookies.get("SESSIONID")

        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = urllib.parse.parse_qs(raw, keep_blank_values=True)
        token = (form.get("csrf_token", [""])[0])

        with STORE_LOCK:
            if not sid or sid not in SESSION_STORE:
                self.send_response(403)
                set_security_headers(self)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Forbidden: no/invalid session")
                return

            session = SESSION_STORE[sid]
            sess_token = session.get("csrf")
            if not token or not sess_token or session.get("used"):
                self.send_response(403)
                set_security_headers(self)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Forbidden: missing/used CSRF token")
                return

            # constant-time compare
            if not secrets.compare_digest(token, sess_token):
                self.send_response(403)
                set_security_headers(self)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Forbidden: invalid CSRF token")
                return

            display = (form.get("displayName", [""])[0])[:100]
            email = (form.get("email", [""])[0])[:254]
            session["settings"]["displayName"] = display
            session["settings"]["email"] = email

            # rotate token (one-time use)
            session["used"] = True
            session["csrf"] = gen_id()
            session["used"] = False

        self.send_response(200)
        set_security_headers(self)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Settings updated securely.")

def run_server(port):
    httpd = socketserver.ThreadingTCPServer(("localhost", port), Handler)
    httpd.daemon_threads = True
    return httpd

if __name__ == "__main__":
    PORT = 8090
    srv = run_server(PORT)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)

    print(f"Running Python tests against http://localhost:{PORT}")

    # Helper cookie jar and functions
    def store_cookies(headers, jar):
        for k, v in headers:
            if k.lower() == "set-cookie":
                main = v.split(";", 1)[0]
                if "=" in main:
                    ck, cv = main.split("=", 1)
                    jar[ck.strip()] = cv.strip()

    def jar_header(jar):
        if not jar:
            return ""
        return "; ".join([f"{k}={v}" for k, v in jar.items()])

    def extract_token(html):
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        return m.group(1) if m else None

    # Test 1: GET then POST success
    jar1 = {}
    conn = http.client.HTTPConnection("localhost", PORT, timeout=3)
    conn.request("GET", "/settings")
    r1 = conn.getresponse()
    html1 = r1.read().decode()
    store_cookies(r1.getheaders(), jar1)
    token1 = extract_token(html1)
    params = urllib.parse.urlencode({"csrf_token": token1, "displayName": "Alice", "email": "alice@example.com"})
    conn.request("POST", "/settings", params, {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": jar_header(jar1)
    })
    r1b = conn.getresponse()
    print("Test1 status=", r1b.status)  # expect 200
    r1b.read()

    # Test 2: Missing token -> 403
    params = urllib.parse.urlencode({"displayName": "Bob", "email": "bob@example.com"})
    conn.request("POST", "/settings", params, {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": jar_header(jar1)
    })
    r2 = conn.getresponse()
    print("Test2 status=", r2.status)  # expect 403
    r2.read()

    # Test 3: Invalid token -> 403
    params = urllib.parse.urlencode({"csrf_token": "invalid", "displayName": "Mallory", "email": "mallory@example.com"})
    conn.request("POST", "/settings", params, {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": jar_header(jar1)
    })
    r3 = conn.getresponse()
    print("Test3 status=", r3.status)  # expect 403
    r3.read()

    # Test 4: Valid token but no cookie -> 403
    jar2 = {}
    conn.request("GET", "/settings")
    r4a = conn.getresponse()
    html2 = r4a.read().decode()
    store_cookies(r4a.getheaders(), jar2)
    token2 = extract_token(html2)
    params = urllib.parse.urlencode({"csrf_token": token2, "displayName": "Eve", "email": "eve@example.com"})
    # No cookie header sent
    conn.request("POST", "/settings", params, {
        "Content-Type": "application/x-www-form-urlencoded"
    })
    r4 = conn.getresponse()
    print("Test4 status=", r4.status)  # expect 403
    r4.read()

    # Test 5: One-time token reuse should fail
    jar3 = {}
    conn.request("GET", "/settings")
    r5a = conn.getresponse()
    html3 = r5a.read().decode()
    store_cookies(r5a.getheaders(), jar3)
    token3 = extract_token(html3)
    params = urllib.parse.urlencode({"csrf_token": token3, "displayName": "Carol", "email": "carol@example.com"})
    conn.request("POST", "/settings", params, {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": jar_header(jar3)
    })
    r5b = conn.getresponse()
    r5b.read()
    # Reuse same token
    params = urllib.parse.urlencode({"csrf_token": token3, "displayName": "Carol2", "email": "carol2@example.com"})
    conn.request("POST", "/settings", params, {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": jar_header(jar3)
    })
    r5c = conn.getresponse()
    print("Test5 first status=", 200, "second status=", r5c.status)  # expect 200 then 403
    r5c.read()

    conn.close()
    srv.shutdown()
    t.join(timeout=1)